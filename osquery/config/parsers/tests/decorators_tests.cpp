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

#include "osquery/config/parsers/decorators.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_bool(disable_decorators);
DECLARE_bool(decorations_top_level);

class DecoratorsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    // Read config content manually.
    readFile(kTestDataPath + "test_parse_items.conf", content_);

    // Construct a config map, the typical output from `Config::genConfig`.
    config_data_["awesome"] = content_;
    Config::get().reset();
    clearDecorations("awesome");

    // Backup the current decorator status.
    decorator_status_ = FLAGS_disable_decorators;
    FLAGS_disable_decorators = true;
  }

  void TearDown() override {
    Config::get().reset();
    FLAGS_disable_decorators = decorator_status_;
  }

 protected:
  std::string content_;
  std::map<std::string, std::string> config_data_;
  bool decorator_status_{false};
};

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_list) {
  // Assume the decorators are disabled.
  Config::get().update(config_data_);
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
  Config::get().update(config_data_);

  QueryLogItem item;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 3U);
  EXPECT_EQ(item.decorations["load_test"], "test");
}

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_run_interval) {
  // Prevent loads from executing.
  FLAGS_disable_decorators = true;
  Config::get().update(config_data_);

  // Mimic the schedule's execution.
  FLAGS_disable_decorators = false;
  runDecorators(DECORATE_INTERVAL, 60);

  QueryLogItem item;
  item.epoch = 0L;
  item.counter = 0L;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 2U);
  EXPECT_EQ(item.decorations.at("internal_60_test"), "test");

  std::string log_line;
  serializeQueryLogItemJSON(item, log_line);
  std::string expected =
      "{\"snapshot\":\"\",\"action\":\"snapshot\",\"name\":\"\","
      "\"hostIdentifier\":\"\",\"calendarTime\":\"\",\"unixTime\":\"0\","
      "\"epoch\":\"0\",\"counter\":\"0\","
      "\"decorations\":{\"internal_60_test\":\"test\",\"one\":\"1\"}}\n";
  EXPECT_EQ(log_line, expected);

  // Now clear and run again.
  clearDecorations("awesome");
  runDecorators(DECORATE_INTERVAL, 60 * 60);

  QueryLogItem second_item;
  getDecorations(second_item.decorations);
  ASSERT_EQ(second_item.decorations.size(), 2U);
}

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_run_load_top_level) {
  // Re-enable the decorators, then update the config.
  // The 'load' decorator set should run every time the config is updated.
  FLAGS_disable_decorators = false;
  // enable top level decorations for the test
  FLAGS_decorations_top_level = true;
  Config::get().update(config_data_);

  // make sure decorations object still exists
  QueryLogItem item;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 3U);
  EXPECT_EQ(item.decorations["load_test"], "test");

  // searialize the QueryLogItem and make sure decorations go top level
  pt::ptree tree;
  auto status = serializeQueryLogItem(item, tree);
  std::string expected = "test";
  std::string result = tree.get("load_test", "none");
  EXPECT_EQ(result, expected);

  // disable top level decorations
  FLAGS_decorations_top_level = false;
}
}
