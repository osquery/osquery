/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdlib.h>

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include "osquery/core/test_util.h"
#include "osquery/logger/plugins/aws_util.h"

namespace osquery {

DECLARE_string(aws_access_key_id);
DECLARE_string(aws_secret_access_key);
DECLARE_string(aws_profile_name);
DECLARE_string(aws_region);
DECLARE_string(aws_sts_region);

static const char* kAwsProfileFileEnvVar = "AWS_SHARED_CREDENTIALS_FILE";
static const char* kAwsAccessKeyEnvVar = "AWS_ACCESS_KEY_ID";
static const char* kAwsSecretKeyEnvVar = "AWS_SECRET_ACCESS_KEY";

class AwsUtilTests : public testing::Test {};

TEST_F(AwsUtilTests, test_get_credentials) {
  // Set a good path for the credentials file
  std::string profile_path = kTestDataPath + "/aws/credentials";
  setenv(kAwsProfileFileEnvVar, profile_path.c_str(), true);

  // Clear any values for the other AWS env vars
  unsetenv(kAwsAccessKeyEnvVar);
  unsetenv(kAwsSecretKeyEnvVar);

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

  setenv(kAwsAccessKeyEnvVar, "ENV_ACCESS_KEY_ID", true);
  setenv(kAwsSecretKeyEnvVar, "env_secret_key", true);
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

TEST_F(AwsUtilTests, test_get_region) {
  Aws::Region region;

  // Test good region flag
  FLAGS_aws_region = "us-west-1";
  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(Aws::Region::US_WEST_1, region);

  // Test bad region flag
  FLAGS_aws_region = "foo";
  ASSERT_EQ(Status(1, "Invalid aws_region specified: foo"), getAWSRegion(region));

  // Test good sts region flag
  FLAGS_aws_sts_region = "us-east-1";
  ASSERT_EQ(Status(0), getAWSRegion(region, true));
  ASSERT_EQ(Aws::Region::US_EAST_1, region);

  // Test bad sts region flag
  FLAGS_aws_sts_region = "bar";
  ASSERT_EQ(Status(1, "Invalid aws_region specified: bar"), getAWSRegion(region, true));

  FLAGS_aws_region = "";

  // Test no credential file, should default to us-east-1
  std::string profile_path = kTestDataPath + "credentials";
  setenv(kAwsProfileFileEnvVar, profile_path.c_str(), true);
  FLAGS_aws_profile_name = "";

  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(Aws::Region::US_EAST_1, region);

  // Set a bad path for the credentials file, with profile name provided,
  // should error
  profile_path = kTestDataPath + "credentials";
  setenv(kAwsProfileFileEnvVar, profile_path.c_str(), true);
  FLAGS_aws_profile_name = "test";

  ASSERT_FALSE(getAWSRegion(region).ok());

  // Set a good path for the credentials file, with profile name
  profile_path = kTestDataPath + "aws/credentials";
  setenv(kAwsProfileFileEnvVar, profile_path.c_str(), true);
  FLAGS_aws_profile_name = "test";

  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(Aws::Region::EU_CENTRAL_1, region);

  FLAGS_aws_profile_name = "default";
  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(Aws::Region::US_WEST_2, region);

  // Should default to "default" and give same result as just above
  FLAGS_aws_profile_name = "";
  ASSERT_EQ(Status(0), getAWSRegion(region));
  ASSERT_EQ(Aws::Region::US_WEST_2, region);
}
}
