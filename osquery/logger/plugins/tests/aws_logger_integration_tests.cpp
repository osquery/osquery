/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>
#include <iostream>
#include <memory>
#include <vector>

#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/logger/plugins/aws_log_forwarder.h"
#include "osquery/tests/test_util.h"

/*
 * A simple test that executes one logString() and exits.
 *
 * This is intended to be run by tools/tests/aws/aws-integration-tests.rb
 * AWS_KINESIS_TEST_CFG environment variable needs to be set to
 * path of config file to use.
 */

using namespace testing;
namespace fs = boost::filesystem;

namespace osquery {

DECLARE_uint64(aws_kinesis_period);

static std::string aws_test_cfg_path = "";
static bool haveCheckedDir = false;

class AwsLoggerIntegrationTests : public testing::Test {
 public:
  void SetUp() override {
    Config::get().reset();

    if (!haveCheckedDir) {
      haveCheckedDir = true;
      const char* env_var_name = "AWS_KINESIS_TEST_CFG";
      const char* tmp = getenv(env_var_name);
      if (nullptr == tmp) {
        LOG(ERROR) << "ENV variable " << std::string(env_var_name)
                   << " not set";
        return;
      }
      aws_test_cfg_path = tmp;
      if (!fs::exists(aws_test_cfg_path)) {
        LOG(ERROR) << "aws_test_cfg_path does not exist:" << aws_test_cfg_path;
        aws_test_cfg_path = "";
      }
    }
  }
  void TearDown() override {
    Config::get().reset();

    // if we don't do this cleanup, Dispatcher will segfault
    PluginRef plugin = Registry::get().plugin("logger", "aws_kinesis");
    if (plugin && (Registry::get().getActive("logger") == "aws_kinesis")) {
      plugin->tearDown();
      Dispatcher::joinServices();
    }
  }
};

bool _loadConfig() {
  EXPECT_FALSE(aws_test_cfg_path.empty());

  if (aws_test_cfg_path.empty()) {
    return true;
  }

  std::string config_file_content = "";
  std::map<std::string, std::string> config_data;

  auto path = aws_test_cfg_path;
  readFile(path, config_file_content);
  if (config_file_content.empty()) {
    LOG(ERROR) << "Unable to read config file:" << path;
    EXPECT_TRUE(false);
    return true;
  }
  config_data["testconfig"] = config_file_content;
  Config::get().update(config_data);

  LOG(WARNING) << "loaded config file:" << path;

  return false;
}

TEST_F(AwsLoggerIntegrationTests, log_one) {
  if (_loadConfig()) {
    return;
  }

  EXPECT_TRUE(Registry::get().setActive("logger", "aws_kinesis"));

  auto status = logString(
      "{ \"some\" : \"value\", \"zero\" : 0, \"vrai\" : true }", "added");

  EXPECT_TRUE(status.ok());
  std::this_thread::sleep_for(std::chrono::seconds(2));
}

} // namespace osquery
