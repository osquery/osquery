/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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

  ASSERT_TRUE(data.doc().HasMember("events"));
  ASSERT_TRUE(data.doc()["events"].HasMember("environment_variables"));
  ASSERT_TRUE(data.doc()["events"]["environment_variables"].IsArray());
  for (const auto& var :
       data.doc()["events"]["environment_variables"].GetArray()) {
    std::string value = var.GetString();
    EXPECT_TRUE(value == "foo" || value == "bar");
  }

  // Reset the configuration.
  c.reset();
}
}
