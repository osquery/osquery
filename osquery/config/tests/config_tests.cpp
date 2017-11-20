/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/packs.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/core/process.h"
#include "osquery/tests/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_uint64(config_refresh);
DECLARE_uint64(config_accelerated_refresh);

const std::string kConfigTestNonBlacklistQuery{
    "pack_unrestricted_pack_process_heartbeat"};

// Blacklist testing methods, internal to config implementations.
extern void restoreScheduleBlacklist(std::map<std::string, size_t>& blacklist);
extern void saveScheduleBlacklist(
    const std::map<std::string, size_t>& blacklist);

class ConfigTests : public testing::Test {
 public:
  ConfigTests() {
    Config::get().reset();
  }

 protected:
  void SetUp() {
    refresh_ = FLAGS_config_refresh;
    FLAGS_config_refresh = 0;

    createMockFileStructure();
  }

  void TearDown() {
    tearDownMockFileStructure();

    FLAGS_config_refresh = refresh_;
  }

 protected:
  Status load() {
    return Config::get().load();
  }

  void setLoaded() {
    Config::get().loaded_ = true;
  }

  Config& get() {
    return Config::get();
  }

 private:
  size_t refresh_{0};
};

class TestConfigPlugin : public ConfigPlugin {
 public:
  TestConfigPlugin() {
    gen_config_count_ = 0;
    gen_pack_count_ = 0;
  }

  Status genConfig(std::map<std::string, std::string>& config) override {
    gen_config_count_++;
    if (fail_) {
      return Status(1);
    }

    std::string content;
    auto s = readFile(kTestDataPath + "test_noninline_packs.conf", content);
    config["data"] = content;
    return s;
  }

  Status genPack(const std::string& name,
                 const std::string& value,
                 std::string& pack) override {
    gen_pack_count_++;
    getUnrestrictedPack().toString(pack);
    return Status();
  }

 public:
  std::atomic<size_t> gen_config_count_{0};
  std::atomic<size_t> gen_pack_count_{0};
  std::atomic<bool> fail_{false};
};

TEST_F(ConfigTests, test_plugin) {
  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<TestConfigPlugin>();
  rf.registry("config")->add("test", plugin);
  // Change the active config plugin.
  EXPECT_TRUE(rf.setActive("config", "test").ok());

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  EXPECT_EQ(status.ok(), true);
  EXPECT_EQ(status.toString(), "OK");

  Registry::call("config", {{"action", "genConfig"}});
  EXPECT_EQ(2U, plugin->gen_config_count_);
  rf.registry("config")->remove("test");
}

TEST_F(ConfigTests, test_invalid_content) {
  std::string bad_json = "{\"options\": {},}";
  ASSERT_NO_THROW(get().update({{"bad_source", bad_json}}));
}

TEST_F(ConfigTests, test_strip_comments) {
  std::string json_comments =
      "// Comment\n // Comment //\n  # Comment\n# Comment\n{\"options\":{}}";

  // Test support for stripping C++ and hash style comments from config JSON.
  auto actual = json_comments;
  stripConfigComments(actual);
  std::string expected = "{\"options\":{}}\n";
  EXPECT_EQ(actual, expected);

  // Make sure the config update source logic applies the stripping.
  EXPECT_TRUE(get().update({{"data", json_comments}}));
}

TEST_F(ConfigTests, test_schedule_blacklist) {
  auto current_time = getUnixTime();
  std::map<std::string, size_t> blacklist;
  saveScheduleBlacklist(blacklist);
  restoreScheduleBlacklist(blacklist);
  EXPECT_EQ(blacklist.size(), 0U);

  // Create some entries.
  blacklist["test_1"] = current_time * 2;
  blacklist["test_2"] = current_time * 3;
  saveScheduleBlacklist(blacklist);
  blacklist.clear();
  restoreScheduleBlacklist(blacklist);
  ASSERT_EQ(blacklist.count("test_1"), 1U);
  ASSERT_EQ(blacklist.count("test_2"), 1U);
  EXPECT_EQ(blacklist.at("test_1"), current_time * 2);
  EXPECT_EQ(blacklist.at("test_2"), current_time * 3);

  // Now save an expired query.
  blacklist["test_1"] = 1;
  saveScheduleBlacklist(blacklist);
  blacklist.clear();

  // When restoring, the values below the current time will not be included.
  restoreScheduleBlacklist(blacklist);
  EXPECT_EQ(blacklist.size(), 1U);
}

TEST_F(ConfigTests, test_pack_noninline) {
  auto& rf = RegistryFactory::get();
  rf.registry("config")->add("test", std::make_shared<TestConfigPlugin>());
  // Change the active config plugin.
  EXPECT_TRUE(rf.setActive("config", "test").ok());

  // Get a specialized config/test plugin.
  const auto& plugin =
      std::dynamic_pointer_cast<TestConfigPlugin>(rf.plugin("config", "test"));

  this->load();
  // Expect the test plugin to have recorded 1 pack.
  // This value is incremented when its genPack method is called.
  EXPECT_EQ(plugin->gen_pack_count_, 1U);

  int total_packs = 0;
  // Expect the config to have recorded a pack for the inline and non-inline.
  get().packs(
      [&total_packs](const std::shared_ptr<Pack>& pack) { total_packs++; });
  EXPECT_EQ(total_packs, 2);
  rf.registry("config")->remove("test");
}

TEST_F(ConfigTests, test_pack_restrictions) {
  auto doc = getExamplePacksConfig();
  auto& packs = doc.doc()["packs"];
  for (const auto& pack : packs.GetObject()) {
    get().addPack(pack.name.GetString(), "", pack.value);
  }

  std::map<std::string, bool> results = {
      {"unrestricted_pack", true},
      {"discovery_pack", false},
      {"fake_version_pack", false},
      // Although this is a valid discovery query, there is no SQL plugin in
      // the core tests.
      {"valid_discovery_pack", false},
      {"restricted_pack", false},
  };

  get().packs(([&results](std::shared_ptr<Pack>& pack) {
    if (results[pack->getName()]) {
      EXPECT_TRUE(pack->shouldPackExecute())
          << "Pack " << pack->getName() << " should have executed";
    } else {
      EXPECT_FALSE(pack->shouldPackExecute())
          << "Pack " << pack->getName() << " should not have executed";
    }
  }));
}

TEST_F(ConfigTests, test_pack_removal) {
  size_t pack_count = 0;
  get().packs(([&pack_count](std::shared_ptr<Pack>& pack) { pack_count++; }));
  EXPECT_EQ(pack_count, 0U);

  pack_count = 0;
  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());
  get().packs(([&pack_count](std::shared_ptr<Pack>& pack) { pack_count++; }));
  EXPECT_EQ(pack_count, 1U);

  pack_count = 0;
  get().removePack("unrestricted_pack");
  get().packs(([&pack_count](std::shared_ptr<Pack>& pack) { pack_count++; }));
  EXPECT_EQ(pack_count, 0U);
}

TEST_F(ConfigTests, test_content_update) {
  // Read config content manually.
  std::string content;
  readFile(kTestDataPath + "test_parse_items.conf", content);

  // Create the output of a `genConfig`.
  std::map<std::string, std::string> config_data;
  config_data["awesome"] = content;

  // Update, then clear, packs should have been cleared.
  get().update(config_data);
  size_t count = 0;
  auto packCounter = [&count](std::shared_ptr<Pack>& pack) { count++; };
  get().packs(packCounter);
  EXPECT_GT(count, 0U);

  // Now clear.
  config_data["awesome"] = "";
  get().update(config_data);
  count = 0;
  get().packs(packCounter);
  EXPECT_EQ(count, 0U);
}

TEST_F(ConfigTests, test_get_scheduled_queries) {
  std::vector<std::string> query_names;
  std::vector<ScheduledQuery> queries;
  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());
  get().scheduledQueries(
      ([&queries](const std::string&, const ScheduledQuery& query) {
        queries.push_back(query);
      }));

  auto expected_size = getUnrestrictedPack().doc()["queries"].MemberCount();
  EXPECT_EQ(queries.size(), expected_size)
      << "The number of queries in the schedule (" << queries.size()
      << ") should equal " << expected_size;
  ASSERT_FALSE(query_names.empty());

  // Construct a schedule blacklist and place the first scheduled query.
  std::map<std::string, size_t> blacklist;
  std::string query_name = query_names[0];
  blacklist[query_name] = getUnixTime() * 2;
  saveScheduleBlacklist(blacklist);
  blacklist.clear();

  // When the blacklist is edited externally, the config must re-read.
  get().reset();
  get().addPack("unrestricted_pack", "", getUnrestrictedPack());

  // Clear the query names in the scheduled queries and request again.
  query_names.clear();
  get().scheduledQueries(
      ([&query_names](const std::string& name, const ScheduledQuery&) {
        query_names.push_back(name);
      }));
  // The query should not exist.
  EXPECT_EQ(std::find(query_names.begin(), query_names.end(), query_name),
            query_names.end());

  // Try again, this time requesting scheduled queries.
  query_names.clear();
  queries.clear();
  get().scheduledQueries(
      ([&queries, &query_names, &query_name](const std::string& name,
                                             const ScheduledQuery& query) {
        if (name == query_name) {
          // Only populate the query we've blacklisted.
          query_names.push_back(name);
          queries.push_back(query);
        }
      }),
      true);
  ASSERT_EQ(query_names.size(), 1_sz);
  EXPECT_EQ(query_names[0], query_name);
  ASSERT_EQ(queries.size(), 1_sz);
  EXPECT_TRUE(queries[0].blacklisted);
}

TEST_F(ConfigTests, test_nonblacklist_query) {
  std::map<std::string, size_t> blacklist;
  blacklist[kConfigTestNonBlacklistQuery] = getUnixTime() * 2;
  saveScheduleBlacklist(blacklist);

  get().reset();
  get().addPack("unrestricted_pack", "", getUnrestrictedPack());

  std::map<std::string, ScheduledQuery> queries;
  get().scheduledQueries(
      ([&queries](const std::string& name, const ScheduledQuery& query) {
        queries[name] = query;
      }));

  // This query cannot be blacklisted.
  auto query = queries.find(kConfigTestNonBlacklistQuery);
  ASSERT_NE(query, queries.end());
  EXPECT_FALSE(query->second.blacklisted);
}

class TestConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    // This config parser requests the follow top-level-config keys.
    return {"dictionary", "dictionary2", "list"};
  }

  Status update(const std::string& source,
                const ParserConfig& config) override {
    // Set a simple boolean indicating the update callin occurred.
    update_called = true;
    // Copy all expected keys into the parser's data.
    for (const auto& key : config) {
      auto obj = data_.getObject();
      data_.copyFrom(key.second.doc(), obj);
      data_.add(key.first, obj, data_.doc());
    }

    // Set parser-rendered additional data.
    auto obj2 = data_.getObject();
    data_.addRef("key2", "value2", obj2);
    data_.add("dictionary3", obj2, data_.doc());
    return Status();
  }

  // Flag tracking that the update method was called.
  static bool update_called;

 private:
  FRIEND_TEST(ConfigTests, test_config_parser);
};

// An intermediate boolean to check parser updates.
bool TestConfigParserPlugin::update_called = false;

TEST_F(ConfigTests, test_get_parser) {
  auto& rf = RegistryFactory::get();
  rf.registry("config_parser")
      ->add("test", std::make_shared<TestConfigParserPlugin>());

  auto s = get().update(getTestConfigMap());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  auto plugin = get().getParser("test");
  EXPECT_TRUE(plugin != nullptr);
  EXPECT_TRUE(plugin.get() != nullptr);

  const auto& parser =
      std::dynamic_pointer_cast<TestConfigParserPlugin>(plugin);
  const auto& doc = parser->getData();

  EXPECT_TRUE(doc.doc().HasMember("list"));
  EXPECT_TRUE(doc.doc().HasMember("dictionary"));
  rf.registry("config_parser")->remove("test");
}

class PlaceboConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {};
  }
  Status update(const std::string&, const ParserConfig&) override {
    return Status();
  }

  /// Make sure configure is called.
  void configure() override {
    configures++;
  }

  size_t configures{0};
};

TEST_F(ConfigTests, test_plugin_reconfigure) {
  auto& rf = RegistryFactory::get();
  // Add a configuration plugin (could be any plugin) that will react to
  // config updates.
  rf.registry("config_parser")
      ->add("placebo", std::make_shared<PlaceboConfigParserPlugin>());

  // Create a config that has been loaded.
  setLoaded();
  get().update({{"data", "{}"}});
  // Get the placebo.
  auto placebo = std::static_pointer_cast<PlaceboConfigParserPlugin>(
      rf.plugin("config_parser", "placebo"));
  EXPECT_EQ(placebo->configures, 1U);

  // Updating with the same content does not reconfigure parsers.
  get().update({{"data", "{}"}});
  EXPECT_EQ(placebo->configures, 1U);

  // Updating with different content will reconfigure.
  get().update({{"data", "{\"options\":{}}"}});
  EXPECT_EQ(placebo->configures, 2U);
  get().update({{"data", "{\"options\":{}}"}});
  EXPECT_EQ(placebo->configures, 2U);

  // Updating with a new source will reconfigure.
  get().update({{"data", "{\"options\":{}}"}, {"data1", "{}"}});
  EXPECT_EQ(placebo->configures, 3U);
  // Updating and not including a source is handled by the config plugin.
  // The config will expect the other source to update asynchronously and does
  // not consider the missing key as a delete request.
  get().update({{"data", "{\"options\":{}}"}});
  EXPECT_EQ(placebo->configures, 3U);

  rf.registry("config_parser")->remove("placebo");
}

TEST_F(ConfigTests, test_pack_file_paths) {
  size_t count = 0;
  auto fileCounter = [&count](const std::string& c,
                              const std::vector<std::string>& files) {
    count += files.size();
  };

  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());
  get().files(fileCounter);
  EXPECT_EQ(count, 2U);

  count = 0;
  get().removePack("unrestricted_pack");
  get().files(fileCounter);
  EXPECT_EQ(count, 0U);

  count = 0;
  get().addPack("restricted_pack", "", getRestrictedPack().doc());
  get().files(fileCounter);
  EXPECT_EQ(count, 0U);

  // Test a more-generic update.
  count = 0;
  get().update({{"data", "{\"file_paths\": {\"new\": [\"/new\"]}}"}});
  get().files(fileCounter);
  EXPECT_EQ(count, 1U);

  count = 0;
  get().update({{"data", "{}"}});
  get().files(fileCounter);
  EXPECT_EQ(count, 0U);
}

void waitForConfig(std::shared_ptr<TestConfigPlugin>& plugin, size_t count) {
  // Max wait of 3 seconds.
  size_t delay = 3000;
  while (delay > 0) {
    if (plugin->gen_config_count_ > count) {
      break;
    }
    delay -= 20;
    sleepFor(20);
  }
}

TEST_F(ConfigTests, test_config_refresh) {
  auto& rf = RegistryFactory::get();
  auto refresh = FLAGS_config_refresh;
  auto refresh_acceleratred = FLAGS_config_accelerated_refresh;

  // Create and add a test plugin.
  auto plugin = std::make_shared<TestConfigPlugin>();
  EXPECT_TRUE(rf.registry("config")->add("test", plugin));
  EXPECT_TRUE(rf.setActive("config", "test"));

  // Reset the configuration and stop the refresh thread.
  get().reset();

  // Stop the existing refresh runner thread.
  Dispatcher::stopServices();
  Dispatcher::joinServices();

  // Set a config_refresh value to convince the Config to start the thread.
  FLAGS_config_refresh = 2;
  FLAGS_config_accelerated_refresh = 1;
  get().setRefresh(FLAGS_config_refresh, 10);

  // Fail the first config load.
  plugin->fail_ = true;

  // The runner will wait at least one refresh-delay.
  auto count = static_cast<size_t>(plugin->gen_config_count_);

  get().load();
  EXPECT_TRUE(get().started_thread_);
  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(get().getRefresh(), FLAGS_config_accelerated_refresh);

  plugin->fail_ = false;
  count = static_cast<size_t>(plugin->gen_config_count_);

  waitForConfig(plugin, count + 1);
  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(get().getRefresh(), FLAGS_config_refresh);

  // Now make the configuration break.
  plugin->fail_ = true;
  count = static_cast<size_t>(plugin->gen_config_count_);

  waitForConfig(plugin, count + 1);
  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(get().getRefresh(), FLAGS_config_accelerated_refresh);

  // Test that the normal acceleration is restored.
  plugin->fail_ = false;
  count = static_cast<size_t>(plugin->gen_config_count_);

  waitForConfig(plugin, count + 1);
  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(get().getRefresh(), FLAGS_config_refresh);

  // Stop the new refresh runner thread.
  Dispatcher::stopServices();
  Dispatcher::joinServices();

  FLAGS_config_refresh = refresh;
  FLAGS_config_accelerated_refresh = refresh_acceleratred;
  rf.registry("config")->remove("test");
}
}
