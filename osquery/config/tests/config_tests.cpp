/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/config/config.h>
#include <osquery/config/config_parser_plugin.h>
#include <osquery/config/config_plugin.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/mock_file_structure.h>
#include <osquery/flags.h>
#include <osquery/packs.h>
#include <osquery/registry.h>
#include <osquery/system.h>
#include <osquery/utils/system/time.h>

#include <boost/filesystem/path.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace osquery {

DECLARE_bool(config_enable_backup);
DECLARE_bool(disable_database);

namespace fs = boost::filesystem;

// Blacklist testing methods, internal to config implementations.
extern void restoreScheduleBlacklist(std::map<std::string, size_t>& blacklist);
extern void saveScheduleBlacklist(
    const std::map<std::string, size_t>& blacklist);

class ConfigTests : public testing::Test {
 public:
  ConfigTests() {
    platformSetup();
    registryAndPluginInit();
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();

    Config::get().reset();
  }

 protected:
  fs::path fake_directory_;

 protected:
  void SetUp() {
    fake_directory_ = fs::canonical(createMockFileStructure());
    createMockFileStructure();
  }

  void TearDown() {
    fs::remove_all(fake_directory_);
  }

 protected:
  Config& get() {
    return Config::get();
  }
};

class EmptyConfigPlugin : public ConfigPlugin {
 public:
  EmptyConfigPlugin() = default;
  Status genConfig(ConfigMap& config) override {
    gen_config_count_++;
    return Status::success();
  }

  Status genPack(const std::string& name,
                 const std::string& value,
                 std::string& pack) override {
    gen_pack_count_++;
    return Status::success();
  }

 public:
  size_t gen_config_count_{0};
  size_t gen_pack_count_{0};
};

TEST_F(ConfigTests, test_plugin) {
  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<EmptyConfigPlugin>();
  rf.registry("config")->add("test", plugin);
  // Change the active config plugin.
  EXPECT_TRUE(rf.setActive("config", "test").ok());

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  EXPECT_EQ(status.ok(), true) << status.what();

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
      {"valid_discovery_pack", true},
      {"restricted_pack", false},
  };

  get().packs(([&results](const Pack& pack) {
    if (results[pack.getName()]) {
      EXPECT_TRUE(const_cast<Pack&>(pack).shouldPackExecute())
          << "Pack " << pack.getName() << " should have executed";
    } else {
      EXPECT_FALSE(const_cast<Pack&>(pack).shouldPackExecute())
          << "Pack " << pack.getName() << " should not have executed";
    }
  }));
}

TEST_F(ConfigTests, test_pack_removal) {
  size_t pack_count = 0;
  get().packs(([&pack_count](const Pack& pack) { pack_count++; }));
  EXPECT_EQ(pack_count, 0U);

  pack_count = 0;
  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());
  get().packs(([&pack_count](const Pack& pack) { pack_count++; }));
  EXPECT_EQ(pack_count, 1U);

  pack_count = 0;
  get().removePack("unrestricted_pack");
  get().packs(([&pack_count](const Pack& pack) { pack_count++; }));
  EXPECT_EQ(pack_count, 0U);
}

TEST_F(ConfigTests, test_content_update) {
  const std::string source{"awesome"};

  // Read config content manually.
  std::string content;
  readFile(getTestConfigDirectory() / "test_parse_items.conf", content);

  // Create the output of a `genConfig`.
  std::map<std::string, std::string> config_data;
  config_data[source] = content;

  // Update, then clear, packs should have been cleared.
  get().update(config_data);
  auto source_hash = get().getHash(source);
  EXPECT_EQ("fb0973b39c70db16655effbca532d4aa93381e59", source_hash);

  size_t count = 0;
  auto packCounter = [&count](const Pack& pack) { count++; };
  get().packs(packCounter);
  EXPECT_GT(count, 0U);

  // Now clear.
  config_data[source] = "";
  get().update(config_data);
  count = 0;
  get().packs(packCounter);
  EXPECT_EQ(count, 0U);
}

TEST_F(ConfigTests, test_get_scheduled_queries) {
  std::vector<std::string> query_names;
  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());
  get().scheduledQueries(
      ([&query_names](std::string name, const ScheduledQuery& query) {
        query_names.push_back(std::move(name));
      }));

  auto expected_size = getUnrestrictedPack().doc()["queries"].MemberCount();
  EXPECT_EQ(query_names.size(), expected_size)
      << "The number of queries in the schedule (" << query_names.size()
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
  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());

  // Clear the query names in the scheduled queries and request again.
  query_names.clear();
  get().scheduledQueries(
      ([&query_names](std::string name, const ScheduledQuery&) {
        query_names.push_back(std::move(name));
      }));
  // The query should not exist.
  EXPECT_EQ(std::find(query_names.begin(), query_names.end(), query_name),
            query_names.end());

  // Try again, this time requesting scheduled queries.
  query_names.clear();
  bool blacklisted = false;
  get().scheduledQueries(([&blacklisted, &query_names, &query_name](
                              std::string name, const ScheduledQuery& query) {
                           if (name == query_name) {
                             // Only populate the query we've blacklisted.
                             query_names.push_back(std::move(name));
                             blacklisted = query.blacklisted;
                           }
                         }),
                         true);
  ASSERT_EQ(query_names.size(), std::size_t{1});
  EXPECT_EQ(query_names[0], query_name);
  EXPECT_TRUE(blacklisted);
}

TEST_F(ConfigTests, test_nonblacklist_query) {
  std::map<std::string, size_t> blacklist;

  const std::string kConfigTestNonBlacklistQuery{
      "pack_unrestricted_pack_process_heartbeat"};

  blacklist[kConfigTestNonBlacklistQuery] = getUnixTime() * 2;
  saveScheduleBlacklist(blacklist);

  get().reset();
  get().addPack("unrestricted_pack", "", getUnrestrictedPack().doc());

  std::map<std::string, bool> blacklisted;
  get().scheduledQueries(
      ([&blacklisted](std::string name, const ScheduledQuery& query) {
        blacklisted[name] = query.blacklisted;
      }));

  // This query cannot be blacklisted.
  auto query = blacklisted.find(kConfigTestNonBlacklistQuery);
  ASSERT_NE(query, blacklisted.end());
  EXPECT_FALSE(query->second);
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
    return Status::success();
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

  auto s = get().update(getTestConfigMap("test_parse_items.conf"));
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
    return Status::success();
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

TEST_F(ConfigTests, test_config_backup) {
  get().reset();
  const ConfigMap expected_config = {{"a", "b"}, {"c", "d"}};
  get().backupConfig(expected_config);
  const auto config = get().restoreConfigBackup();
  EXPECT_TRUE(config);
  EXPECT_EQ(*config, expected_config);
}
} // namespace osquery
