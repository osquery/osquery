/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/http_client.h>
#include <osquery/remote/transports/tls.h>
// clang-format on

#include <fstream>
#include <mutex>
#include <sstream>
#include <string>

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <aws/core/Aws.h>
#include <aws/core/Region.h>
#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/standard/StandardHttpRequest.h>
#include <aws/core/http/standard/StandardHttpResponse.h>

#include <aws/sts/model/AssumeRoleRequest.h>
#include <aws/sts/model/Credentials.h>

#include <osquery/core/flags.h>
#include <osquery/core/shutdown.h>
#include <osquery/logger/data_logger.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/aws/aws_util.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

namespace pt = boost::property_tree;

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
FLAG(string, aws_session_token, "", "AWS STS session token");
FLAG(bool,
     aws_enable_proxy,
     false,
     "Enable proxying of HTTP/HTTPS requests in AWS client config");
FLAG(string,
     aws_proxy_scheme,
     "https",
     "Proxy HTTP scheme for use in AWS client config (http or https, default "
     "https)");
FLAG(string, aws_proxy_host, "", "Proxy host for use in AWS client config");
FLAG(uint32, aws_proxy_port, 0, "Proxy port for use in AWS client config");
FLAG(string,
     aws_proxy_username,
     "",
     "Proxy username for use in AWS client config");
FLAG(string,
     aws_proxy_password,
     "",
     "Proxy password for use in AWS client config");
FLAG(bool, aws_debug, false, "Enable AWS SDK debug logging");

FLAG(uint32,
     aws_imdsv2_request_attempts,
     3,
     "How many attempts to do at requesting an IMDSv2 token");

FLAG(uint32,
     aws_imdsv2_request_interval,
     3,
     "Base seconds to wait between attempts at requesting an IMDSv2 token. "
     "Scales quadratically with the number of attempts");

FLAG(bool,
     aws_disable_imdsv1_fallback,
     false,
     "Whether to disable support for IMDSv1 and fail if an IMDSv2 token could "
     "not be retrieved");

/// EC2 instance latestmetadata URL
const std::string kEc2MetadataUrl =
    "http://" + http::kInstanceMetadataAuthority + "/latest/";

/// EC2 instance identity document URL
const std::string kEc2IdentityDocument =
    kEc2MetadataUrl + "dynamic/instance-identity/document";

/// Hypervisor UUID file
const std::string kHypervisorUuid = "/sys/hypervisor/uuid";

/// URL resource to request IMDSv2 API token
const std::string kImdsTokenResource = "api/token";

/// Token header to be used in HTTP GET requests for IMDSv2 API calls
const std::string kImdsTokenHeader = "x-aws-ec2-metadata-token";

/// Header for specifying TTL for IMDSv2 API token
const std::string kImdsTokenTtlHeader = "x-aws-ec2-metadata-token-ttl-seconds";

/// Default TTL value for IMDSv2 API token, set as per the AWS SDK
const std::string kImdsTokenTtlDefaultValue = "21600";

/// Map of AWS region name to AWS::Region enum.
static const std::set<std::string> kAwsRegions = {
    "af-south-1",     "ap-east-1",     "ap-northeast-1", "ap-northeast-2",
    "ap-northeast-3", "ap-south-1",    "ap-southeast-1", "ap-southeast-2",
    "ca-central-1",   "cn-north-1",    "cn-northwest-1", "eu-central-1",
    "eu-north-1",     "eu-south-1",    "eu-west-1",      "eu-west-2",
    "eu-west-3",      "me-south-1",    "sa-east-1",      "us-east-1",
    "us-east-2",      "us-gov-east-1", "us-gov-west-1",  "us-west-1",
    "us-west-2"};

// Default AWS region to use when no region set in flags or profile
static RegionName kDefaultAWSRegion = Aws::Region::US_EAST_1;

// To protect the access to the AWS instance id and region that are being cached
static std::mutex cached_values_mutex;

namespace {
bool validateIMDSV2RequestAttempts(const char* flagname, std::uint32_t value) {
  if (value == 0) {
    std::string error_message =
        "Only values higher than 0 are supported for " + std::string(flagname);
    osquery::systemLog(error_message);
    std::cerr << error_message << std::endl;

    return false;
  }

  return true;
}
}; // namespace

DEFINE_validator(aws_imdsv2_request_attempts, validateIMDSV2RequestAttempts);

std::shared_ptr<Aws::Http::HttpClient>
OsqueryHttpClientFactory::CreateHttpClient(
    const Aws::Client::ClientConfiguration& clientConfiguration) const {
  return std::make_shared<OsqueryHttpClient>();
}

std::shared_ptr<Aws::Http::HttpRequest>
OsqueryHttpClientFactory::CreateHttpRequest(
    const Aws::String& uri,
    Aws::Http::HttpMethod method,
    const Aws::IOStreamFactory& streamFactory) const {
  return CreateHttpRequest(Aws::Http::URI(uri), method, streamFactory);
}

std::shared_ptr<Aws::Http::HttpRequest>
OsqueryHttpClientFactory::CreateHttpRequest(
    const Aws::Http::URI& uri,
    Aws::Http::HttpMethod method,
    const Aws::IOStreamFactory& streamFactory) const {
  auto request = std::make_shared<Standard::StandardHttpRequest>(uri, method);
  request->SetResponseStreamFactory(streamFactory);

  return request;
}

std::shared_ptr<Aws::Http::HttpResponse> OsqueryHttpClient::MakeRequest(
    const std::shared_ptr<Aws::Http::HttpRequest>& request_ptr,
    Aws::Utils::RateLimits::RateLimiterInterface* readLimiter,
    Aws::Utils::RateLimits::RateLimiterInterface* writeLimiter) const {
  auto& request = *request_ptr.get();

  // AWS allows rate limiters to be passed around, but we are doing rate
  // limiting on the logger plugin side and so don't implement this.
  if (readLimiter != nullptr || writeLimiter != nullptr) {
    LOG(WARNING) << "Read/write limiters are unsupported";
  }

  Aws::Http::URI uri = request.GetUri();
  uri.SetPath(Aws::Http::URI::URLEncodePath(uri.GetPath()));
  Aws::String url = uri.GetURIString();

  http::Client client(TLSTransport().getInternalOptions());
  http::Request req(url);

  for (const auto& requestHeader : request.GetHeaders()) {
    req << http::Request::Header(requestHeader.first, requestHeader.second);
  }

  std::string body;
  if (request.GetContentBody()) {
    std::stringstream ss;
    ss << request.GetContentBody()->rdbuf();
    body = ss.str();
  }

  auto response = std::make_shared<Standard::StandardHttpResponse>(request_ptr);
  http::Response resp;

  try {
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
      LOG(ERROR) << "osquery-http_client does not support HTTP PATCH";

      response->SetResponseCode(Aws::Http::HttpResponseCode::NOT_IMPLEMENTED);
      return response;

    case Aws::Http::HttpMethod::HTTP_DELETE:
      resp = client.delete_(req);
      break;

    default:
      LOG(ERROR) << "Unrecognized HTTP Method used: "
                 << static_cast<int>(request.GetMethod());

      response->SetResponseCode(Aws::Http::HttpResponseCode::NOT_IMPLEMENTED);
      return response;

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
    /* NOTE: This exception must NOT be passed by reference. */
    LOG(ERROR) << "Exception making HTTP "
               << Aws::Http::HttpMethodMapper::GetNameForHttpMethod(
                      request.GetMethod())
               << " request to URL (" << url << "): " << e.what();

    response->SetResponseCode(
        static_cast<Aws::Http::HttpResponseCode>(resp.status()));
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
  uint64_t current_time = osquery::getUnixTime();

  // config provides STS creds that includes the token
  if (!FLAGS_aws_session_token.empty()) {
    if (access_key_id_.empty()) {
      initAwsSdk();
      access_key_id_ = FLAGS_aws_access_key_id;
      secret_access_key_ = FLAGS_aws_secret_access_key;
      session_token_ = FLAGS_aws_session_token;
      VLOG(1) << "Using provided aws_session_token for id starting with: "
              << FLAGS_aws_access_key_id.substr(0, 8);
    }
    return Aws::Auth::AWSCredentials(
        access_key_id_, secret_access_key_, session_token_);
  }

  // Pull new STS credentials if not cached from a previous run.
  if (token_expire_time_ <= current_time) {
    // Create and setup a STS client to pull our temporary credentials.
    VLOG(1) << "Generating new AWS STS credentials";

    // If we have not setup an AWS client yet, we must do so here.
    if (access_key_id_.empty()) {
      initAwsSdk();
    }

    Status s = makeAWSClient<Aws::STS::STSClient>(client_, "", false);
    if (!s.ok()) {
      LOG(WARNING) << "Error creating AWS client: " << s.what();
      return Aws::Auth::AWSCredentials("", "");
    }

    Model::AssumeRoleRequest sts_r;
    sts_r.SetRoleArn(FLAGS_aws_sts_arn_role);
    sts_r.SetRoleSessionName(FLAGS_aws_sts_session_name);
    sts_r.SetDurationSeconds(static_cast<int>(FLAGS_aws_sts_timeout));

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
      LOG(ERROR) << "Failed to create STS temporary credentials, error: "
                 << sts_outcome.GetError().GetMessage();
    }
  }
  return Aws::Auth::AWSCredentials(
      access_key_id_, secret_access_key_, session_token_);
}

OsqueryAWSCredentialsProviderChain::OsqueryAWSCredentialsProviderChain(bool sts)
    : AWSCredentialsProviderChain() {
  // The order of the AddProvider calls determines the order in which the
  // provider chain attempts to retrieve credentials.
  if (!FLAGS_aws_session_token.empty() ||
      (sts && !FLAGS_aws_sts_arn_role.empty())) {
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
    return Status(1, std::string("Error reading profile file: ") + e.what());
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
      if (FLAGS_aws_debug) {
        options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Debug;
      }
      options.httpOptions.httpClientFactory_create_fn = []() {
        return std::make_shared<OsqueryHttpClientFactory>();
      };
      Aws::InitAPI(options);
    });
  } catch (const std::system_error&) {
    LOG(ERROR) << "call_once was not executed for initAwsSdk";
  }
}

boost::optional<std::pair<std::string, std::string>> getInstanceIDAndRegion() {
  static std::string cached_id;
  static std::string cached_region;
  static bool init_successfully = false;

  std::lock_guard<std::mutex> lock(cached_values_mutex);

  if (init_successfully) {
    return {{cached_id, cached_region}};
  }

  initAwsSdk();
  http::Request req(kEc2IdentityDocument);
  auto opt_token = getIMDSToken();
  if (opt_token.has_value()) {
    req << http::Request::Header(kImdsTokenHeader, *opt_token);
  } else if (FLAGS_aws_disable_imdsv1_fallback) {
    /* If the IMDSv2 token cannot be retrieved and we disabled IMDSv1,
       we cannot attempt to do a request, so return with empty results. */
    VLOG(1) << "Could not retrieve an IMDSv2 token to request the instance id "
               "and region. The IMDSv1 fallback is disabled";
    return boost::none;
  }

  http::Client::Options options;
  options.timeout(3);
  http::Client client(options);

  try {
    http::Response res = client.get(req);
    if (res.status() == 200) {
      pt::ptree tree;
      std::stringstream ss(res.body());
      pt::read_json(ss, tree);
      cached_id = tree.get<std::string>("instanceId", ""),
      cached_region = tree.get<std::string>("region", ""),
      VLOG(1) << "EC2 instance ID: " << cached_id
              << ". Region: " << cached_region;
    }
  } catch (const std::system_error& e) {
    VLOG(1) << "Error getting EC2 instance information: " << e.what();
    return boost::none;
  }

  init_successfully = true;

  return {{cached_id, cached_region}};
}

boost::optional<std::string> getIMDSToken() {
  std::string token;
  http::Request req(kEc2MetadataUrl + kImdsTokenResource);
  http::Client::Options options;
  options.timeout(3);
  http::Client client(options);
  req << http::Request::Header(kImdsTokenTtlHeader, kImdsTokenTtlDefaultValue);

  std::uint32_t attempts = 0;
  std::uint32_t interval = FLAGS_aws_imdsv2_request_interval;
  while (attempts < FLAGS_aws_imdsv2_request_attempts) {
    try {
      http::Response res = client.put(req, "", "");
      token = res.status() == 200 ? res.body() : "";
    } catch (const std::system_error& e) {
      VLOG(1) << "Request for " << kImdsTokenResource
              << " failed: " << e.what();
    } catch (const std::runtime_error& e) {
      VLOG(1) << "Request for " << kImdsTokenResource
              << " failed: " << e.what();
    }

    if (token.empty()) {
      if (attempts < FLAGS_aws_imdsv2_request_attempts) {
        auto should_shutdown =
            osquery::waitTimeoutOrShutdown(std::chrono::seconds(interval));
        if (should_shutdown) {
          return boost::none;
        }

        interval *= FLAGS_aws_imdsv2_request_interval;
        ++attempts;
      }
      continue;
    }

    break;
  }

  if (attempts == FLAGS_aws_imdsv2_request_attempts) {
    LOG(ERROR) << "Failed " << FLAGS_aws_imdsv2_request_attempts
               << " attempts at retrieving an IMDSv2 token";
    return boost::none;
  }

  return token;
}

Status getAWSRegion(std::string& region, bool sts, bool validate_region) {
  // First try using the explicit region flags (STS or otherwise).
  if (sts && !FLAGS_aws_sts_region.empty()) {
    auto index = kAwsRegions.find(FLAGS_aws_sts_region);
    if (index != kAwsRegions.end() || !validate_region) {
      VLOG(1) << "Using AWS STS region from flag: " << FLAGS_aws_sts_region;
      region = FLAGS_aws_sts_region;
      return Status(0);
    } else {
      return Status(1, "Invalid aws_region specified: " + FLAGS_aws_sts_region);
    }
  }

  if (!FLAGS_aws_region.empty()) {
    auto index = kAwsRegions.find(FLAGS_aws_region);
    if (index != kAwsRegions.end() || !validate_region) {
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
  return Status::success();
}

void setAWSProxy(Aws::Client::ClientConfiguration& config) {
  if (FLAGS_aws_enable_proxy) {
    config.proxyScheme =
        Aws::Http::SchemeMapper::FromString(FLAGS_aws_proxy_scheme.c_str());
    config.proxyHost = FLAGS_aws_proxy_host;
    config.proxyPort = FLAGS_aws_proxy_port;
    config.proxyUserName = FLAGS_aws_proxy_username;
    config.proxyPassword = FLAGS_aws_proxy_password;
  }
}
} // namespace osquery
