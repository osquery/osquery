/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
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

#include "osquery/logger/plugins/aws_util.h"
#include "osquery/remote/transports/tls.h"

namespace pt = boost::property_tree;
namespace bn = boost::network;
namespace http = boost::network::http;
namespace uri = boost::network::uri;

namespace osquery {

FLAG(string, aws_access_key_id, "", "AWS access key ID override");
FLAG(string, aws_secret_access_key, "", "AWS secret access key override");
FLAG(string,
     aws_profile_name,
     "",
     "AWS config profile to use for auth and region config");
FLAG(string, aws_region, "", "AWS region override");
FLAG(string, aws_sts_arn_role, "", "AWS STS arn role");
FLAG(string, aws_sts_region, "", "AWS STS region override");
FLAG(string, aws_sts_session_name, "default", "AWS STS session name");
FLAG(uint64,
     aws_sts_timeout,
     3600,
     "duration in seconds which the sts assume role temp creds are valid "
     "(default 3600)");

// Map of AWS region name string -> AWS::Region enum
static const std::map<std::string, Aws::Region> kAwsRegions = {
    {"us-east-1", Aws::Region::US_EAST_1},
    {"us-west-1", Aws::Region::US_WEST_1},
    {"us-west-2", Aws::Region::US_WEST_2},
    {"eu-west-1", Aws::Region::EU_WEST_1},
    {"eu-central-1", Aws::Region::EU_CENTRAL_1},
    {"ap-southeast-1", Aws::Region::AP_SOUTHEAST_1},
    {"ap-southeast-2", Aws::Region::AP_SOUTHEAST_2},
    {"ap-northeast-1", Aws::Region::AP_NORTHEAST_1},
    {"ap-northeast-2", Aws::Region::AP_NORTHEAST_2},
    {"sa-east-1", Aws::Region::SA_EAST_1}};
// Default AWS region to use when no region set in flags or profile
static const Aws::Region kDefaultAWSRegion = Aws::Region::US_EAST_1;

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
  auto request =
      std::make_shared<Aws::Http::Standard::StandardHttpRequest>(uri, method);
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
    LOG(WARNING) << "Read/write limiters currently unsupported.";
  }

  Aws::Http::URI uri = request.GetUri();
  uri.SetPath(Aws::Http::URI::URLEncodePath(uri.GetPath()));
  Aws::String url = uri.GetURIString();

  http::client client;
  http::client::request req(url);

  for (const auto& requestHeader : request.GetHeaders()) {
    req << bn::header(requestHeader.first, requestHeader.second);
  }

  std::string body;
  if (request.GetContentBody()) {
    std::stringstream ss;
    ss << request.GetContentBody()->rdbuf();
    body = ss.str();
  }

  auto response =
      std::make_shared<Aws::Http::Standard::StandardHttpResponse>(request);
  try {
    http::client::response resp;

    switch (request.GetMethod()) {
    case Aws::Http::HttpMethod::HTTP_GET:
      resp = client.get(req);
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
    LOG(ERROR) << "Exception making HTTP request to url (" << url
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
    LOG(WARNING) << "Only one of aws_access_key_id and aws_secret_access_key "
                    "were specified. Ignoring.";
    return Aws::Auth::AWSCredentials("", "");
  }
  return Aws::Auth::AWSCredentials(FLAGS_aws_access_key_id,
                                   FLAGS_aws_secret_access_key);
}

Aws::Auth::AWSCredentials
OsquerySTSAWSCredentialsProvider::GetAWSCredentials() {
  // Grab system time in seconds since epoch for token experation checks
  auto now = std::chrono::system_clock::now();
  auto epoch = now.time_since_epoch();
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch);
  // Pull new STS creds if we dont have them cached from a previous run,
  // otherwise return cached STS creds
  if (token_expire_time <= seconds.count()) {
    // Create and setup a STS client to pull our temp creds
    VLOG(1) << "Generate new AWS STS credentials.";
    initAwsSdk();
    Status s = makeAWSClient<Aws::STS::STSClient>(sts_client_, false);
    Aws::STS::Model::AssumeRoleRequest sts_r;
    sts_r.SetRoleArn(FLAGS_aws_sts_arn_role);
    sts_r.SetRoleSessionName(FLAGS_aws_sts_session_name);
    sts_r.SetDurationSeconds(FLAGS_aws_sts_timeout);
    // Pull our STS creds
    Aws::STS::Model::AssumeRoleOutcome sts_outcome =
        sts_client_->AssumeRole(sts_r);
    if (sts_outcome.IsSuccess()) {
      Aws::STS::Model::AssumeRoleResult sts_result = sts_outcome.GetResult();
      // Cache our credentials for later use
      sts_access_key_id = sts_result.GetCredentials().GetAccessKeyId();
      sts_secret_access_key = sts_result.GetCredentials().GetSecretAccessKey();
      sts_session_token = sts_result.GetCredentials().GetSessionToken();
      // Calculate when our credentials will expire
      token_expire_time = seconds.count() + FLAGS_aws_sts_timeout;
    }
  }
  return Aws::Auth::AWSCredentials(sts_access_key_id, sts_secret_access_key,
                                   sts_session_token);
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

Status getAWSRegionFromProfile(Aws::Region& region) {
  std::string profile_dir =
      Aws::Auth::ProfileConfigFileAWSCredentialsProvider::GetProfileDirectory();
  pt::ptree tree;
  try {
    pt::ini_parser::read_ini(profile_dir + "/config", tree);
  } catch (const pt::ini_parser::ini_parser_error& e) {
    return Status(1, std::string("Error reading profile file: ") + e.what());
  }

  // For some reason, profile names are prefixed with "profile ", except for
  // "default" which is not.
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
    return Status(1, "AWS region not found for profile: " +
                         FLAGS_aws_profile_name);
  }

  std::string region_string = key_it->second.data();
  if (kAwsRegions.count(region_string) > 0) {
    region = kAwsRegions.at(region_string);
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

Status getAWSRegion(Aws::Region& region, bool sts) {
  // First try using the flag aws_region
  if (sts && !FLAGS_aws_sts_region.empty()) {
    if (kAwsRegions.count(FLAGS_aws_sts_region) > 0) {
      VLOG(1) << "Using AWS STS region from flag: " << FLAGS_aws_sts_region;
      region = kAwsRegions.at(FLAGS_aws_sts_region);
      return Status(0);
    } else {
      return Status(1, "Invalid aws_region specified: " + FLAGS_aws_sts_region);
    }
  }
  if (!FLAGS_aws_region.empty()) {
    if (kAwsRegions.count(FLAGS_aws_region) > 0) {
      VLOG(1) << "Using AWS region from flag: " << FLAGS_aws_region;
      region = kAwsRegions.at(FLAGS_aws_region);
      return Status(0);
    } else {
      return Status(1, "Invalid aws_region specified: " + FLAGS_aws_region);
    }
  }

  // Try finding in profile, but use default if that fails and no profile name
  // was specified
  Status s = getAWSRegionFromProfile(region);
  if (s.ok() || !FLAGS_aws_profile_name.empty()) {
    VLOG(1) << "Using AWS region from profile: "
            << Aws::RegionMapper::GetRegionName(region);
    return s;
  }
  region = kDefaultAWSRegion;
  VLOG(1) << "Using default AWS region: "
          << Aws::RegionMapper::GetRegionName(region);
  return Status(0);
}
}
