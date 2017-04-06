/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>
#include <sstream>
#include <string>

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <aws/core/Aws.h>
#include <aws/core/Region.h>
#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/standard/StandardHttpRequest.h>
#include <aws/core/http/standard/StandardHttpResponse.h>

#include <aws/sts/model/AssumeRoleRequest.h>
#include <aws/sts/model/Credentials.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/json.h"
#include "osquery/logger/plugins/aws_util.h"
#include "osquery/remote/transports/tls.h"

namespace pt = boost::property_tree;
namespace bn = boost::network;
namespace uri = boost::network::uri;

namespace Standard = Aws::Http::Standard;
namespace Model = Aws::STS::Model;

namespace osquery {

FLAG(string, aws_access_key_id, "", "AWS access key ID");
FLAG(string, aws_secret_access_key, "", "AWS secret access key");
FLAG(string,
     aws_profile_name,
     "",
     "AWS profile for authentication and region configuration");
FLAG(string, aws_region, "", "AWS region");
FLAG(string, aws_sts_arn_role, "", "AWS STS ARN role");
FLAG(string, aws_sts_region, "", "AWS STS region");
FLAG(string, aws_sts_session_name, "default", "AWS STS session name");
FLAG(uint64,
     aws_sts_timeout,
     3600,
     "AWS STS assume role credential validity in seconds (default 3600)");

/// Map of AWS region name to AWS::Region enum.
static const std::set<std::string> kAwsRegions = {"us-east-1",
                                                  "us-west-1",
                                                  "us-west-2",
                                                  "eu-west-1",
                                                  "eu-central-1",
                                                  "ap-southeast-1",
                                                  "ap-southeast-2",
                                                  "ap-northeast-1",
                                                  "ap-northeast-2",
                                                  "sa-east-1",
                                                  "ap-south-1",
                                                  "us-east-2",
                                                  "ca-central-1",
                                                  "eu-west-1",
                                                  "eu-west-2"};

// Default AWS region to use when no region set in flags or profile
static RegionName kDefaultAWSRegion = Aws::Region::US_EAST_1;

std::shared_ptr<Aws::Http::HttpClient>
NetlibHttpClientFactory::CreateHttpClient(
    const Aws::Client::ClientConfiguration& clientConfiguration) const {
  return std::make_shared<NetlibHttpClient>();
}

std::shared_ptr<Aws::Http::HttpRequest>
NetlibHttpClientFactory::CreateHttpRequest(
    const Aws::String& uri,
    Aws::Http::HttpMethod method,
    const Aws::IOStreamFactory& streamFactory) const {
  return CreateHttpRequest(Aws::Http::URI(uri), method, streamFactory);
}

std::shared_ptr<Aws::Http::HttpRequest>
NetlibHttpClientFactory::CreateHttpRequest(
    const Aws::Http::URI& uri,
    Aws::Http::HttpMethod method,
    const Aws::IOStreamFactory& streamFactory) const {
  auto request = std::make_shared<Standard::StandardHttpRequest>(uri, method);
  request->SetResponseStreamFactory(streamFactory);

  return request;
}

std::shared_ptr<Aws::Http::HttpResponse> NetlibHttpClient::MakeRequest(
    Aws::Http::HttpRequest& request,
    Aws::Utils::RateLimits::RateLimiterInterface* readLimiter,
    Aws::Utils::RateLimits::RateLimiterInterface* writeLimiter) const {
  // AWS allows rate limiters to be passed around, but we are doing rate
  // limiting on the logger plugin side and so don't implement this.
  if (readLimiter != nullptr || writeLimiter != nullptr) {
    LOG(WARNING) << "Read/write limiters are unsupported";
  }

  Aws::Http::URI uri = request.GetUri();
  uri.SetPath(Aws::Http::URI::URLEncodePath(uri.GetPath()));
  Aws::String url = uri.GetURIString();

  bn::http::client client = TLSTransport().getClient();
  bn::http::client::request req(url);

  for (const auto& requestHeader : request.GetHeaders()) {
    req << bn::header(requestHeader.first, requestHeader.second);
  }

  std::string body;
  if (request.GetContentBody()) {
    std::stringstream ss;
    ss << request.GetContentBody()->rdbuf();
    body = ss.str();
  }

  auto response = std::make_shared<Standard::StandardHttpResponse>(request);
  try {
    bn::http::client::response resp;

    switch (request.GetMethod()) {
    case Aws::Http::HttpMethod::HTTP_GET:
      resp = client.get(req);
      if (resp.status() == 301 || resp.status() == 302) {
        VLOG(1) << "Attempting custom redirect as cpp-netlib does not support "
                   "redirects";
        for (const auto& header : resp.headers()) {
          if (header.first == "Location") {
            req.uri(header.second);
            resp = client.get(req);
          }
        }
      }
      break;
    case Aws::Http::HttpMethod::HTTP_POST:
      resp = client.post(req, body, request.GetContentType());
      break;
    case Aws::Http::HttpMethod::HTTP_PUT:
      resp = client.put(req, body, request.GetContentType());
      break;
    case Aws::Http::HttpMethod::HTTP_HEAD:
      resp = client.head(req);
      break;
    case Aws::Http::HttpMethod::HTTP_PATCH:
      LOG(ERROR) << "cpp-netlib does not support HTTP PATCH";
      return nullptr;
      break;
    case Aws::Http::HttpMethod::HTTP_DELETE:
      resp = client.delete_(req);
      break;
    default:
      LOG(ERROR) << "Unrecognized HTTP Method used: "
                 << static_cast<int>(request.GetMethod());
      return nullptr;
      break;
    }

    response->SetResponseCode(
        static_cast<Aws::Http::HttpResponseCode>(resp.status()));

    for (const auto& header : resp.headers()) {
      if (header.first == "content-type") {
        response->SetContentType(header.second);
      }
      response->AddHeader(header.first, header.second);
    }

    response->GetResponseBody() << resp.body();

  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception making HTTP request to URL (" << url
               << "): " << e.what();
    return nullptr;
  }

  return response;
}

Aws::Auth::AWSCredentials
OsqueryFlagsAWSCredentialsProvider::GetAWSCredentials() {
  // Note that returning empty credentials means the provider chain will just
  // try the next provider.
  if (FLAGS_aws_access_key_id.empty() ^ FLAGS_aws_secret_access_key.empty()) {
    LOG(WARNING) << "Cannot use AWS credentials: ID or secret missing";
    return Aws::Auth::AWSCredentials("", "");
  }
  return Aws::Auth::AWSCredentials(FLAGS_aws_access_key_id,
                                   FLAGS_aws_secret_access_key);
}

Aws::Auth::AWSCredentials
OsquerySTSAWSCredentialsProvider::GetAWSCredentials() {
  // Grab system time in seconds-since-epoch for token expiration checks.
  size_t current_time = osquery::getUnixTime();

  // Pull new STS credentials if not cached from a previous run.
  if (token_expire_time_ <= current_time) {
    // Create and setup a STS client to pull our temporary credentials.
    VLOG(1) << "Generating new AWS STS credentials";

    // If we have not setup an AWS client yet, we must do so here.
    if (access_key_id_.empty()) {
      initAwsSdk();
    }

    makeAWSClient<Aws::STS::STSClient>(client_, false);
    Model::AssumeRoleRequest sts_r;
    sts_r.SetRoleArn(FLAGS_aws_sts_arn_role);
    sts_r.SetRoleSessionName(FLAGS_aws_sts_session_name);
    sts_r.SetDurationSeconds(FLAGS_aws_sts_timeout);

    // Pull our STS credentials.
    Model::AssumeRoleOutcome sts_outcome = client_->AssumeRole(sts_r);
    if (sts_outcome.IsSuccess()) {
      Model::AssumeRoleResult sts_result = sts_outcome.GetResult();
      // Cache our credentials for later use.
      access_key_id_ = sts_result.GetCredentials().GetAccessKeyId();
      secret_access_key_ = sts_result.GetCredentials().GetSecretAccessKey();
      session_token_ = sts_result.GetCredentials().GetSessionToken();
      // Calculate when our credentials will expire.
      token_expire_time_ = current_time + FLAGS_aws_sts_timeout;
    } else {
      LOG(ERROR) << "Failed to create STS temporary credentials: "
                    "No STS policy exists for the AWS user/role";
    }
  }
  return Aws::Auth::AWSCredentials(
      access_key_id_, secret_access_key_, session_token_);
}

OsqueryAWSCredentialsProviderChain::OsqueryAWSCredentialsProviderChain(bool sts)
    : AWSCredentialsProviderChain() {
  // The order of the AddProvider calls determines the order in which the
  // provider chain attempts to retrieve credentials.
  if (sts && !FLAGS_aws_sts_arn_role.empty()) {
    AddProvider(std::make_shared<OsquerySTSAWSCredentialsProvider>());
  }

  AddProvider(std::make_shared<OsqueryFlagsAWSCredentialsProvider>());
  if (!FLAGS_aws_profile_name.empty()) {
    AddProvider(
        std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(
            FLAGS_aws_profile_name.c_str()));
  }

  AddProvider(std::make_shared<Aws::Auth::EnvironmentAWSCredentialsProvider>());
  AddProvider(
      std::make_shared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>());
  AddProvider(
      std::make_shared<Aws::Auth::InstanceProfileCredentialsProvider>());
}

Status getAWSRegionFromProfile(std::string& region) {
  pt::ptree tree;
  try {
    auto profile_dir = Aws::Auth::ProfileConfigFileAWSCredentialsProvider::
        GetProfileDirectory();
    pt::ini_parser::read_ini(profile_dir + "/config", tree);
  } catch (const pt::ini_parser::ini_parser_error& e) {
    LOG(ERROR) << "Error reading profile file: " << e.what();
    return Status(1, e.what());
  }

  // Profile names are prefixed with "profile ", except for "default".
  std::string profile_key = FLAGS_aws_profile_name;
  if (!profile_key.empty() && profile_key != "default") {
    profile_key = "profile " + profile_key;
  } else {
    profile_key = "default";
  }

  auto section_it = tree.find(profile_key);
  if (section_it == tree.not_found()) {
    return Status(1, "AWS profile not found: " + FLAGS_aws_profile_name);
  }

  auto key_it = section_it->second.find("region");
  if (key_it == section_it->second.not_found()) {
    return Status(
        1, "AWS region not found for profile: " + FLAGS_aws_profile_name);
  }

  std::string region_string = key_it->second.data();
  auto index = kAwsRegions.find(region_string);
  if (index != kAwsRegions.end()) {
    region = region_string;
  } else {
    return Status(1, "Invalid aws_region in profile: " + region_string);
  }

  return Status(0);
}

void initAwsSdk() {
  static std::once_flag once_flag;
  try {
    std::call_once(once_flag, []() {
      Aws::SDKOptions options;
      options.httpOptions.httpClientFactory_create_fn = []() {
        return std::make_shared<NetlibHttpClientFactory>();
      };
      Aws::InitAPI(options);
    });
  } catch (const std::system_error& e) {
    LOG(ERROR) << "call_once was not executed for initAwsSdk";
  }
}

Status getAWSRegion(std::string& region, bool sts) {
  // First try using the explicit region flags (STS or otherwise).
  if (sts && !FLAGS_aws_sts_region.empty()) {
    auto index = kAwsRegions.find(FLAGS_aws_sts_region);
    if (index != kAwsRegions.end()) {
      VLOG(1) << "Using AWS STS region from flag: " << FLAGS_aws_sts_region;
      region = FLAGS_aws_sts_region;
      return Status(0);
    } else {
      return Status(1, "Invalid aws_region specified: " + FLAGS_aws_sts_region);
    }
  }

  if (!FLAGS_aws_region.empty()) {
    auto index = kAwsRegions.find(FLAGS_aws_region);
    if (index != kAwsRegions.end()) {
      VLOG(1) << "Using AWS region from flag: " << FLAGS_aws_region;
      region = FLAGS_aws_region;
      return Status(0);
    } else {
      return Status(1, "Invalid aws_region specified: " + FLAGS_aws_region);
    }
  }

  // Try finding in profile.
  auto s = getAWSRegionFromProfile(region);
  if (s.ok() || !FLAGS_aws_profile_name.empty()) {
    VLOG(1) << "Using AWS region from profile: " << region;
    return s;
  }

  // Use the default region.
  region = kDefaultAWSRegion;
  VLOG(1) << "Using default AWS region: " << region;
  return Status(0);
}

Status appendLogTypeToJson(const std::string& log_type, std::string& log) {
  if (log_type.empty()) {
    return Status(1, "log_type is empty");
  }

  if (log.empty()) {
    return Status(1, "original JSON is empty");
  }

  pt::ptree params;
  try {
    std::stringstream input;
    input << log;
    pt::read_json(input, params);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1,
                  std::string("JSON deserialization exception: ") + e.what());
  }

  params.put<std::string>("log_type", log_type);

  std::ostringstream output;
  try {
    pt::write_json(output, params, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, std::string("JSON serialization exception: ") + e.what());
  }

  log = output.str();

  // Get rid of newline
  if (!log.empty()) {
    log.pop_back();
  }
  return Status(0, "OK");
}
}
