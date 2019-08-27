/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
#include <vector>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry.h>
#include <osquery/registry_interface.h>
#include <osquery/system.h>

namespace osquery {

DECLARE_bool(disable_database);

class EventsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    Initializer::platformSetup();
    registryAndPluginInit();

    // Force registry to use ephemeral database plugin
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();
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
