/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <vector>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry.h>
#include <osquery/registry/registry_interface.h>

namespace osquery {

class EventsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(EventsConfigParserPluginTests, test_get_event) {
  // Reset the schedule in case other tests were modifying.
  auto& c = Config::get();
  c.reset();

  // Generate content to update/add to the config.
  std::string content;
  auto s =
      readFile(getTestConfigDirectory() / "test_parse_items.conf", content);
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
