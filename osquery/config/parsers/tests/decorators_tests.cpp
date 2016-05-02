/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/test_util.h"
#include "osquery/config/parsers/decorators.h"

namespace osquery {

DECLARE_bool(disable_decorators);

class DecoratorsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    // Read config content manually.
    readFile(kTestDataPath + "test_parse_items.conf", content_);

    // Construct a config map, the typical output from `Config::genConfig`.
    config_data_["awesome"] = content_;
    Config::getInstance().reset();
    clearDecorations("awesome");

    // Backup the current decorator status.
    decorator_status_ = FLAGS_disable_decorators;
    FLAGS_disable_decorators = true;
  }

  void TearDown() override {
    Config::getInstance().reset();
    FLAGS_disable_decorators = decorator_status_;
  }

 protected:
  std::string content_;
  std::map<std::string, std::string> config_data_;
  bool decorator_status_{false};
};

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_list) {
  // Assume the decorators are disabled.
  Config::getInstance().update(config_data_);
  auto parser = Config::getParser("decorators");
  EXPECT_NE(parser, nullptr);

  // Expect the decorators to be disabled by default.
  QueryLogItem item;
  getDecorations(item.decorations);
  EXPECT_EQ(item.decorations.size(), 0U);
}

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_run_load) {
  // Re-enable the decorators, then update the config.
  // The 'load' decorator set should run every time the config is updated.
  FLAGS_disable_decorators = false;
  Config::getInstance().update(config_data_);

  QueryLogItem item;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 3U);
  EXPECT_EQ(item.decorations["load_test"], "test");
}

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_run_interval) {
  // Prevent loads from executing.
  FLAGS_disable_decorators = true;
  Config::getInstance().update(config_data_);

  // Mimic the schedule's execution.
  FLAGS_disable_decorators = false;
  runDecorators(DECORATE_INTERVAL, 60);

  QueryLogItem item;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 2U);
  EXPECT_EQ(item.decorations.at("internal_60_test"), "test");

  std::string log_line;
  serializeQueryLogItemJSON(item, log_line);
  std::string expected =
      "{\"snapshot\":\"\",\"action\":\"snapshot\",\"decorations\":{\"internal_"
      "60_test\":\"test\",\"one\":\"1\"},\"name\":\"\",\"hostIdentifier\":\"\","
      "\"calendarTime\":\"\",\"unixTime\":\"0\"}\n";
  EXPECT_EQ(log_line, expected);

  // Now clear and run again.
  clearDecorations("awesome");
  runDecorators(DECORATE_INTERVAL, 60 * 60);

  QueryLogItem second_item;
  getDecorations(second_item.decorations);
  ASSERT_EQ(second_item.decorations.size(), 2U);
}
}
