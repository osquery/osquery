/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/registry.h>

#include "osquery/tests/test_util.h"

namespace osquery {

class EventsConfigParserPluginTests : public testing::Test {};

TEST_F(EventsConfigParserPluginTests, test_get_event) {
  // Reset the schedule in case other tests were modifying.
  auto& c = Config::get();
  c.reset();

  // Generate content to update/add to the config.
  std::string content;
  auto s = readFile(kTestDataPath + "test_parse_items.conf", content);
  EXPECT_TRUE(s.ok());
  std::map<std::string, std::string> config;
  config["awesome"] = content;

  // Send our synthetic config.
  s = c.update(config);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  // Retrieve a basic events parser.
  auto plugin = Config::get().getParser("events");
  EXPECT_TRUE(plugin != nullptr);
  const auto& data = plugin->getData();

  EXPECT_EQ(data.count("events"), 1U);
  EXPECT_GT(data.get_child("events").count("environment_variables"), 0U);
  for (const auto& var : data.get_child("events.environment_variables")) {
    EXPECT_TRUE(var.second.data() == "foo" || var.second.data() == "bar");
  }

  // Reset the configuration.
  c.reset();
}
}
