/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

pt::ptree getExamplePacksConfig();
pt::ptree getUnrestrictedPack();
pt::ptree getPackWithDiscovery();
pt::ptree getPackWithFakeVersion();

// The config_path flag is defined in the filesystem config plugin.
DECLARE_string(config_path);

std::map<std::string, std::string> getTestConfigMap() {
  std::string content;
  readFile(kTestDataPath + "test_parse_items.conf", content);
  std::map<std::string, std::string> config;
  config["awesome"] = content;
  return config;
}

class ConfigTests : public testing::Test {
 public:
  ConfigTests() {
    Registry::setActive("config", "filesystem");
    FLAGS_config_path = kTestDataPath + "test.config";
  }

 protected:
  void SetUp() {
    createMockFileStructure();
    Registry::setUp();
    Config::getInstance().load();
  }

  void TearDown() { tearDownMockFileStructure(); }
};

class TestConfigPlugin : public ConfigPlugin {
 public:
  TestConfigPlugin() {
    genConfigCount = 0;
    genPackCount = 0;
  }

  Status genConfig(std::map<std::string, std::string>& config) {
    genConfigCount++;
    std::string content;
    auto s = readFile(kTestDataPath + "test_noninline_packs.conf", content);
    config["data"] = content;
    return s;
  }

  Status genPack(const std::string& name,
                 const std::string& value,
                 std::string& pack) {
    genPackCount++;
    std::stringstream ss;
    pt::write_json(ss, getUnrestrictedPack(), false);
    pack = ss.str();
    return Status(0, "OK");
  }

  int genConfigCount;
  int genPackCount;
};

TEST_F(ConfigTests, test_plugin) {
  Registry::add<TestConfigPlugin>("config", "test");

  // Change the active config plugin.
  EXPECT_TRUE(Registry::setActive("config", "test").ok());

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  EXPECT_EQ(status.ok(), true);
  EXPECT_EQ(status.toString(), "OK");
}

TEST_F(ConfigTests, test_bad_config_update) {
  std::string bad_json = "{\"options\": {},}";
  ASSERT_NO_THROW(Config::getInstance().update({{"bad_source", bad_json}}));
}

class TestConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() {
    // This config parser requests the follow top-level-config keys.
    return {"dictionary", "dictionary2", "list"};
  }

  Status update(const std::map<std::string, pt::ptree>& config) {
    // Set a simple boolean indicating the update callin occurred.
    update_called = true;
    // Copy all expected keys into the parser's data.
    for (const auto& key : config) {
      data_.put_child(key.first, key.second);
    }

    // Set parser-rendered additional data.
    data_.put("dictionary3.key2", "value2");
    return Status(0, "OK");
  }

  // Flag tracking that the update method was called.
  static bool update_called;

 private:
  FRIEND_TEST(ConfigTests, test_config_parser);
};

// An intermediate boolean to check parser updates.
bool TestConfigParserPlugin::update_called = false;

TEST_F(ConfigTests, test_parse) {
  auto c = Config();
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  for (const auto& pack : packs) {
    c.addPack(Pack(pack.first, pack.second));
  }
  for (Pack& p : c.schedule_) {
    EXPECT_TRUE(p.shouldPackExecute());
  }
}

TEST_F(ConfigTests, test_remove) {
  auto c = Config();
  c.addPack(Pack("kernel", getUnrestrictedPack()));
  c.removePack("kernel");
  for (Pack& pack : c.schedule_) {
    EXPECT_NE("kernel", pack.getName());
  }
}

TEST_F(ConfigTests, test_add_remove_pack) {
  auto c = Config();
  auto first = c.schedule_.begin();
  auto last = c.schedule_.end();
  EXPECT_EQ(std::distance(first, last), 0);

  c.addPack(Pack("kernel", getUnrestrictedPack()));
  first = c.schedule_.begin();
  last = c.schedule_.end();
  EXPECT_EQ(std::distance(first, last), 1);

  c.removePack("kernel");
  first = c.schedule_.begin();
  last = c.schedule_.end();
  EXPECT_EQ(std::distance(first, last), 0);
}

TEST_F(ConfigTests, test_get_scheduled_queries) {
  std::vector<ScheduledQuery> queries;
  auto c = Config();
  c.addPack(Pack("kernel", getUnrestrictedPack()));
  c.scheduledQueries(
      ([&queries](const std::string&, const ScheduledQuery& query) {
        queries.push_back(query);
      }));
  EXPECT_EQ(queries.size(), getUnrestrictedPack().get_child("queries").size());
}

TEST_F(ConfigTests, test_get_parser) {
  Registry::add<TestConfigParserPlugin>("config_parser", "test");
  EXPECT_TRUE(Registry::setActive("config_parser", "test").ok());

  auto c = Config();
  auto s = c.update(getTestConfigMap());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  auto plugin = Config::getInstance().getParser("test");
  EXPECT_TRUE(plugin != nullptr);
  EXPECT_TRUE(plugin.get() != nullptr);

  const auto& parser =
      std::dynamic_pointer_cast<TestConfigParserPlugin>(plugin);
  auto data = parser->getData();

  EXPECT_EQ(data.count("list"), 1U);
  EXPECT_EQ(data.count("dictionary"), 1);
}

TEST_F(ConfigTests, test_noninline_pack) {
  Registry::add<TestConfigPlugin>("config", "test");

  // Change the active config plugin.
  EXPECT_TRUE(Registry::setActive("config", "test").ok());

  const auto& plugin = std::dynamic_pointer_cast<TestConfigPlugin>(
      Registry::get("config", "test"));

  auto c = Config();
  c.load();
  EXPECT_EQ(plugin->genPackCount, 1);

  int total_packs = 0;
  c.packs([&total_packs](const Pack& pack) { total_packs++; });
  EXPECT_EQ(total_packs, 2);
}
}
