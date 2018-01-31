/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <stdlib.h>

#include <gtest/gtest.h>

#include <osquery/core/process.h>
#include <osquery/logger.h>

#include "osquery/tests/test_util.h"
#include "osquery/utils/aws_util.h"

namespace osquery {

DECLARE_string(aws_access_key_id);
DECLARE_string(aws_secret_access_key);
DECLARE_string(aws_profile_name);
DECLARE_string(aws_region);
DECLARE_string(aws_sts_region);

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
  std::string profile_path = kTestDataPath + "/aws/credentials";
  setEnvVar(kAwsProfileFileEnvVar, profile_path.c_str());

  // Clear any values for the other AWS env vars
  unsetEnvVar(kAwsAccessKeyEnvVar);
  unsetEnvVar(kAwsSecretKeyEnvVar);

  OsqueryAWSCredentialsProviderChain provider;
  Aws::Auth::AWSCredentials credentials("", "");

  FLAGS_aws_access_key_id = "FLAG_ACCESS_KEY_ID";
  FLAGS_aws_secret_access_key = "flag_secret_key";
  // With the flags set, those credentials should be used
  provider = OsqueryAWSCredentialsProviderChain();
  credentials = provider.GetAWSCredentials();
  ASSERT_EQ("FLAG_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
  ASSERT_EQ("flag_secret_key", credentials.GetAWSSecretKey());

  FLAGS_aws_access_key_id = "FLAG_ACCESS_KEY_ID";
  FLAGS_aws_secret_access_key = "flag_secret_key";
  // With the flags set and sts disabled, those credentials should be used
  provider = OsqueryAWSCredentialsProviderChain(false);
  credentials = provider.GetAWSCredentials();
  ASSERT_EQ("FLAG_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
  ASSERT_EQ("flag_secret_key", credentials.GetAWSSecretKey());

  // Profiles are not working on Windows; see the constructor of
  // OsqueryAWSCredentialsProviderChain for more information
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    FLAGS_aws_access_key_id = "";
    FLAGS_aws_secret_access_key = "flag_secret_key";
    // With the flags set improperly, the profile should be used
    provider = OsqueryAWSCredentialsProviderChain();
    credentials = provider.GetAWSCredentials();
    ASSERT_EQ("DEFAULT_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
    ASSERT_EQ("default_secret_key", credentials.GetAWSSecretKey());

    FLAGS_aws_access_key_id = "FLAG_ACCESS_KEY_ID";
    FLAGS_aws_secret_access_key = "";
    // With the flags set improperly, the profile should be used
    provider = OsqueryAWSCredentialsProviderChain();
    credentials = provider.GetAWSCredentials();
    ASSERT_EQ("DEFAULT_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
    ASSERT_EQ("default_secret_key", credentials.GetAWSSecretKey());

    // Clear flags
    FLAGS_aws_access_key_id = "";
    FLAGS_aws_secret_access_key = "";

    setEnvVar(kAwsAccessKeyEnvVar, "ENV_ACCESS_KEY_ID");
    setEnvVar(kAwsSecretKeyEnvVar, "env_secret_key");
    // Now env variables should be the primary source
    provider = OsqueryAWSCredentialsProviderChain();
    credentials = provider.GetAWSCredentials();
    ASSERT_EQ("ENV_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
    ASSERT_EQ("env_secret_key", credentials.GetAWSSecretKey());

    FLAGS_aws_profile_name = "test";
    provider = OsqueryAWSCredentialsProviderChain();
    credentials = provider.GetAWSCredentials();
    // Now the "test" profile should take precedence
    ASSERT_EQ("TEST_ACCESS_KEY_ID", credentials.GetAWSAccessKeyId());
    ASSERT_EQ("test_secret_key", credentials.GetAWSSecretKey());
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
  std::string profile_path = kTestDataPath + "credentials";
  setEnvVar(kAwsProfileFileEnvVar, profile_path.c_str());
  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(std::string(Aws::Region::US_EAST_1), region);

  // Profiles are not working on Windows; see the constructor of
  // OsqueryAWSCredentialsProviderChain for more information
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Set an invalid path for the credentials file with a profile name
    // provided,
    profile_path = kTestDataPath + "credentials";
    setEnvVar(kAwsProfileFileEnvVar, profile_path.c_str());
    FLAGS_aws_profile_name = "test";
    ASSERT_FALSE(getAWSRegion(region).ok());

    // Set a valid path for the credentials file with profile name.
    profile_path = kTestDataPath + "aws/credentials";
    setEnvVar(kAwsProfileFileEnvVar, profile_path.c_str());
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
}
