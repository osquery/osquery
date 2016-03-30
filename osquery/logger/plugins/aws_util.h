/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <memory>

#include <aws/core/Region.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/HttpClient.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/http/standard/StandardHttpResponse.h>

#include <boost/property_tree/ptree.hpp>

namespace osquery {

/**
 * @brief Client factory for the netlib HTTP client
 */
class NetlibHttpClientFactory : public Aws::Http::HttpClientFactory {
 public:
  std::shared_ptr<Aws::Http::HttpClient> CreateHttpClient(
      const Aws::Client::ClientConfiguration &clientConfiguration)
      const override;
};

/**
 * @brief Netlib implementation of AWS HTTP Client
 *
 * AWS uses a libcurl HTTP client by default. We prefer not to use libcurl, so
 * we provide this HTTP client implementation for the AWS SDK to use when
 * querying the APIs. The SDK must be built with -DNO_HTTP_CLIENT=1 to prevent
 * it looking for libcurl when static linking.
 */
class NetlibHttpClient : public Aws::Http::HttpClient {
 public:
  NetlibHttpClient() : HttpClient() {}

  std::shared_ptr<Aws::Http::HttpResponse> MakeRequest(
      Aws::Http::HttpRequest &request,
      Aws::Utils::RateLimits::RateLimiterInterface *readLimiter = nullptr,
      Aws::Utils::RateLimits::RateLimiterInterface *writeLimiter =
          nullptr) const override;
};

/**
 * @brief AWS credentials provider that uses osquery config flags
 *
 * This provider uses the config flags aws_access_key_id and
 * aws_secret_access_key. If only one flag is specified, it returns empty
 * strings so that another provider in the chain can be tried.
 */
class OsqueryFlagsAWSCredentialsProvider
    : public Aws::Auth::AWSCredentialsProvider {
 public:
  OsqueryFlagsAWSCredentialsProvider() : AWSCredentialsProvider() {}

  Aws::Auth::AWSCredentials GetAWSCredentials() override;
};

/**
 * @brief AWS credentials provider chain that prioritizes osquery config
 *
 * This provider attempts to find credentials in the following order, returning
 * the first non-empty credentials it finds:
 * 1. osquery flags (via OsqueryFlagsAWSCredentialsProvider)
 * 2. Profile from the AWS profile file (iff --aws_profile_name is specified)
 * 3. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
 * 4. "default" profile in AWS profile file
 * 5. Profile from the EC2 Instance Metadata Service
 */
class OsqueryAWSCredentialsProviderChain
    : public Aws::Auth::AWSCredentialsProviderChain {
 public:
  OsqueryAWSCredentialsProviderChain();
};

/**
 * @brief Retrieve the Aws::Region from the aws_region flag
 *
 * @param region The Aws::Region to place the result in
 *
 * @return 0 if successful, 1 if the region was not recognized
 */
Status getAWSRegion(Aws::Region& region);

/**
 * @brief Instantiate an AWS client with the appropriate osquery configs
 *
 * This will pull the region and authentication configs from the appropriate
 * places (i.e. using getAWSRegion, OsqueryAWSCredentialsProviderChain),
 * instantiating whichever type of AWS client is passed as the template
 * parameter.
 *
 * @param client Pointer to the client object to instantiate
 *
 * @return 0 if successful, 1 if there was a problem reading configs
 */
template <class Client>
Status makeAWSClient(std::shared_ptr<Client> &client) {
  // Set up client
  Aws::Client::ClientConfiguration client_config;
  Status s = getAWSRegion(client_config.region);
  if (!s.ok()) {
    return s;
  }
  client = std::make_shared<Client>(
      std::make_shared<OsqueryAWSCredentialsProviderChain>(), client_config,
      std::make_shared<NetlibHttpClientFactory>());
  return Status(0);
}
}
