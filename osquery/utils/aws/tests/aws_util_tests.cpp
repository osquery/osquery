/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <stdlib.h>

#include <gtest/gtest.h>

#include <osquery/core/flags.h>
#include <osquery/process/process.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/utils/aws/aws_util.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {

DECLARE_string(aws_access_key_id);
DECLARE_string(aws_secret_access_key);
DECLARE_string(aws_profile_name);
DECLARE_string(aws_region);
DECLARE_string(aws_sts_region);
DECLARE_bool(aws_enable_proxy);
DECLARE_string(aws_proxy_scheme);
DECLARE_string(aws_proxy_host);
DECLARE_uint32(aws_proxy_port);
DECLARE_string(aws_proxy_username);
DECLARE_string(aws_proxy_password);

static const char* kAwsProfileFileEnvVar = "AWS_SHARED_CREDENTIALS_FILE";
static const char* kAwsAccessKeyEnvVar = "AWS_ACCESS_KEY_ID";
static const char* kAwsSecretKeyEnvVar = "AWS_SECRET_ACCESS_KEY";

class AwsUtilTests : public testing::Test {
 public:
  void SetUp() override {
    initAwsSdk();
  }
};

TEST_F(AwsUtilTests, test_get_credentials) {
  // Set a good path for the credentials file
  auto const profile_path = getTestConfigDirectory() / "/aws/credentials";
  setEnvVar(kAwsProfileFileEnvVar, profile_path.string());

  // Clear any values for the other AWS env vars
  unsetEnvVar(kAwsAccessKeyEnvVar);
  unsetEnvVar(kAwsSecretKeyEnvVar);

  Aws::Auth::AWSCredentials credentials("", "");

  FLAGS_aws_access_key_id = "FLAG_ACCESS_KEY_ID";
  FLAGS_aws_secret_access_key = "flag_secret_key";
  {
    // With the flags set, those credentials should be used
    OsqueryAWSCredentialsProviderChain provider;
    credentials = provider.GetAWSCredentials();
    ASSERT_EQ("FLAG_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
    ASSERT_EQ("flag_secret_key", credentials.GetAWSSecretKey());
  }

  FLAGS_aws_access_key_id = "FLAG_ACCESS_KEY_ID";
  FLAGS_aws_secret_access_key = "flag_secret_key";
  {
    // With the flags set and sts disabled, those credentials should be used
    OsqueryAWSCredentialsProviderChain provider(false);
    credentials = provider.GetAWSCredentials();
    ASSERT_EQ("FLAG_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
    ASSERT_EQ("flag_secret_key", credentials.GetAWSSecretKey());
  }

  // Profiles are not working on Windows; see the constructor of
  // OsqueryAWSCredentialsProviderChain for more information
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    FLAGS_aws_access_key_id = "";
    FLAGS_aws_secret_access_key = "flag_secret_key";
    {
      // With the flags set improperly, the profile should be used
      OsqueryAWSCredentialsProviderChain provider;
      credentials = provider.GetAWSCredentials();
      ASSERT_EQ("DEFAULT_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
      ASSERT_EQ("default_secret_key", credentials.GetAWSSecretKey());
    }

    FLAGS_aws_access_key_id = "FLAG_ACCESS_KEY_ID";
    FLAGS_aws_secret_access_key = "";
    {
      // With the flags set improperly, the profile should be used
      OsqueryAWSCredentialsProviderChain provider;
      credentials = provider.GetAWSCredentials();
      ASSERT_EQ("DEFAULT_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
      ASSERT_EQ("default_secret_key", credentials.GetAWSSecretKey());
    }

    // Clear flags
    FLAGS_aws_access_key_id = "";
    FLAGS_aws_secret_access_key = "";

    setEnvVar(kAwsAccessKeyEnvVar, "ENV_ACCESS_KEY_ID");
    setEnvVar(kAwsSecretKeyEnvVar, "env_secret_key");
    {
      // Now env variables should be the primary source
      OsqueryAWSCredentialsProviderChain provider;
      credentials = provider.GetAWSCredentials();
      ASSERT_EQ("ENV_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
      ASSERT_EQ("env_secret_key", credentials.GetAWSSecretKey());
    }

    FLAGS_aws_profile_name = "test";
    {
      OsqueryAWSCredentialsProviderChain provider;
      credentials = provider.GetAWSCredentials();
      // Now the "test" profile should take precedence
      ASSERT_EQ("TEST_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
      ASSERT_EQ("test_secret_key", credentials.GetAWSSecretKey());
    }
  }
}

TEST_F(AwsUtilTests, test_get_region) {
  std::string region;

  // Test valid region flag.
  FLAGS_aws_region = "us-west-1";
  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(std::string(Aws::Region::US_WEST_1), region);

  // Test invalid region flag.
  FLAGS_aws_region = "foo";
  ASSERT_EQ(Status(1, "Invalid aws_region specified: foo"),
            getAWSRegion(region));

  // Test disabled region validation.
  FLAGS_aws_region = "foo";
  ASSERT_EQ(Status(0), getAWSRegion(region, false, false));
  ASSERT_EQ("foo", region);

  // Reset aws_region flag.
  FLAGS_aws_region = "";

  // Test valid STS region flag.
  FLAGS_aws_sts_region = "us-east-1";
  ASSERT_EQ(Status(0), getAWSRegion(region, true));
  ASSERT_EQ(std::string(Aws::Region::US_EAST_1), region);

  // Test invalid STS region flag.
  FLAGS_aws_sts_region = "bar";
  ASSERT_EQ(Status(1, "Invalid aws_region specified: bar"),
            getAWSRegion(region, true));

  // Reset STS and profile flags.
  FLAGS_aws_sts_region = "";
  FLAGS_aws_profile_name = "";

  // Test no credential file, should default to us-east-1
  auto profile_path = getTestConfigDirectory() / "credentials";
  setEnvVar(kAwsProfileFileEnvVar, profile_path.string());
  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(std::string(Aws::Region::US_EAST_1), region);

  // Profiles are not working on Windows; see the constructor of
  // OsqueryAWSCredentialsProviderChain for more information
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Set an invalid path for the credentials file with a profile name
    // provided,
    profile_path = getTestConfigDirectory() / "credentials";
    setEnvVar(kAwsProfileFileEnvVar, profile_path.string());
    FLAGS_aws_profile_name = "test";
    ASSERT_FALSE(getAWSRegion(region).ok());

    // Set a valid path for the credentials file with profile name.
    profile_path = getTestConfigDirectory() / "aws/credentials";
    setEnvVar(kAwsProfileFileEnvVar, profile_path.string());
    FLAGS_aws_profile_name = "test";
    ASSERT_EQ(Status(0), getAWSRegion(region));
    ASSERT_EQ(std::string(Aws::Region::EU_CENTRAL_1), region);

    FLAGS_aws_profile_name = "default";
    ASSERT_EQ(Status(0), getAWSRegion(region));
    ASSERT_EQ(std::string(Aws::Region::US_WEST_2), region);

    // Should default to "default" and give same result as just above
    FLAGS_aws_profile_name = "";
    ASSERT_EQ(Status(0), getAWSRegion(region));
    ASSERT_EQ(std::string(Aws::Region::US_WEST_2), region);
  }
}

TEST_F(AwsUtilTests, test_append_log_type_to_json) {
  Status status;
  std::string output;

  std::string null_json = "";

  status = appendLogTypeToJson("result", null_json);
  ASSERT_FALSE(status.ok());
  ASSERT_EQ(status.getCode(), 1);

  const std::string expected_empty = "{\"log_type\":\"result\"}";
  std::string empty_json = "{}";

  status = appendLogTypeToJson("result", empty_json);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(expected_empty, empty_json);

  const std::string expected_full =
      "{\"severity\":\"0\",\"log_type\":\"status\"}";
  std::string full_json = "{\"severity\":\"0\"}";

  status = appendLogTypeToJson("status", full_json);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(expected_full, full_json);
}

TEST_F(AwsUtilTests, test_set_proxy_valid) {
  Aws::Client::ClientConfiguration client_config;

  const std::string host = "foo.bar.baz";
  const uint64_t port = 3000;
  const std::string username = "foo_username";
  const std::string password = "bar_password";

  // Test with valid proxy values.
  FLAGS_aws_enable_proxy = true;
  FLAGS_aws_proxy_scheme = "http";
  FLAGS_aws_proxy_host = host;
  FLAGS_aws_proxy_port = port;
  FLAGS_aws_proxy_username = username;
  FLAGS_aws_proxy_password = password;

  setAWSProxy(client_config);

  ASSERT_EQ(Aws::Http::Scheme::HTTP, client_config.proxyScheme);
  ASSERT_EQ(host, client_config.proxyHost);
  ASSERT_EQ(port, client_config.proxyPort);
  ASSERT_EQ(username, client_config.proxyUserName);
  ASSERT_EQ(password, client_config.proxyPassword);
}

TEST_F(AwsUtilTests, test_set_proxy_invalid) {
  Aws::Client::ClientConfiguration client_config;

  const std::string host = "foo.bar.baz";
  const uint64_t port = 3000;
  const std::string username = "foo_username";
  const std::string password = "bar_password";

  // Test with invalid proxy scheme value.
  FLAGS_aws_enable_proxy = true;
  FLAGS_aws_proxy_scheme = "htpt";
  FLAGS_aws_proxy_host = host;
  FLAGS_aws_proxy_port = port;
  FLAGS_aws_proxy_username = username;
  FLAGS_aws_proxy_password = password;

  setAWSProxy(client_config);

  // Default should be HTTPS for missing/invalid scheme
  ASSERT_EQ(Aws::Http::Scheme::HTTPS, client_config.proxyScheme);
  ASSERT_EQ(host, client_config.proxyHost);
  ASSERT_EQ(port, client_config.proxyPort);
  ASSERT_EQ(username, client_config.proxyUserName);
  ASSERT_EQ(password, client_config.proxyPassword);
}
}
