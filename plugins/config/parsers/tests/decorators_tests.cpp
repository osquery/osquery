/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry.h>
#include <plugins/config/parsers/decorators.h>

namespace osquery {

DECLARE_bool(disable_decorators);
DECLARE_bool(decorations_top_level);
DECLARE_bool(logger_numerics);

class DecoratorsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    // Read config content manually.
    readFile(getTestConfigDirectory() / "test_parse_items.conf", content_);

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
  auto status = Config::get().update(config_data_);
  ASSERT_TRUE(status.ok()) << status.getMessage();

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
  auto status = Config::get().update(config_data_);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  QueryLogItem item;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 3U);
  EXPECT_EQ(item.decorations["load_test"], "test");
}

TEST_F(DecoratorsConfigParserPluginTests, test_decorators_run_interval) {
  // Prevent loads from executing.
  FLAGS_disable_decorators = true;
  auto status = Config::get().update(config_data_);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  // Mimic the schedule's execution.
  FLAGS_disable_decorators = false;
  runDecorators(DECORATE_INTERVAL, 60);

  QueryLogItem item;
  item.epoch = 0L;
  item.counter = 0L;
  item.isSnapshot = true;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 2U);
  EXPECT_EQ(item.decorations.at("internal_60_test"), "test");

  std::string log_line;
  serializeQueryLogItemJSON(item, log_line);
  std::string expected =
      "{\"snapshot\":[],\"action\":\"snapshot\",\"name\":\"\","
      "\"hostIdentifier\":\"\",\"calendarTime\":\"\",\"unixTime\":0,"
      "\"epoch\":0,\"counter\":0,\"numerics\":" +
      std::string(FLAGS_logger_numerics ? "true" : "false") +
      ",\"decorations\":{\"internal_60_test\":\"test\",\"one\":\"1\"}}";
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
  auto status = Config::get().update(config_data_);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  // make sure decorations object still exists
  QueryLogItem item;
  getDecorations(item.decorations);
  ASSERT_EQ(item.decorations.size(), 3U);
  EXPECT_EQ(item.decorations["load_test"], "test");

  // serialize the QueryLogItem and make sure decorations go top level
  auto doc = JSON::newObject();
  status = serializeQueryLogItem(item, doc);
  std::string expected = "test";
  std::string result = doc.doc()["load_test"].GetString();
  EXPECT_EQ(result, expected);

  // disable top level decorations
  FLAGS_decorations_top_level = false;
}
TEST_F(DecoratorsConfigParserPluginTests, test_invalid_decorators) {
  // Prevent loads from executing.
  FLAGS_disable_decorators = true;

  std::map<std::string, std::string> decorators_as_array = {
      {"decorators", "[1,2,3]"}};
  auto status = Config::get().update(decorators_as_array);
  ASSERT_FALSE(status.ok());

  std::map<std::string, std::string> decorators_as_string = {
      {"decorators", "abc"}};
  status = Config::get().update(decorators_as_string);
  ASSERT_FALSE(status.ok());

  std::map<std::string, std::string> decorators_as_number = {
      {"decorators", "1"}};
  status = Config::get().update(decorators_as_number);
  ASSERT_FALSE(status.ok());
}

namespace {

std::string getDecoration(const std::string& name) {
  std::map<std::string, std::string> decorations;
  getDecorations(decorations);
  auto it = decorations.find(name);
  return it == decorations.end() ? "<missing>" : it->second;
}

ConfigParserPlugin::ParserConfig makeDecoratorsConfig(
    const std::string& load_query) {
  auto doc = JSON::newObject();
  EXPECT_TRUE(doc.fromString(R"({"load": [")" + load_query + R"("]})").ok());
  ConfigParserPlugin::ParserConfig config;
  config.emplace("decorators", std::move(doc));
  return config;
}

} // namespace

// Decorator queries run without decorator locks held. A load decorator that
// reads osquery_schedule takes the schedule lock, which a concurrent config
// update holds while it waits for the decorator locks.
TEST_F(DecoratorsConfigParserPluginTests,
       test_concurrent_updates_with_schedule_decorator_no_deadlock) {
  FLAGS_disable_decorators = false;

  auto updates = [](const std::string& source) {
    for (size_t i = 0; i < 100; ++i) {
      // Alternate the config so that every update is applied.
      Config::get().update(
          {{source,
            R"({"schedule": {"q": {"query": "SELECT 1", "interval": 60}},
                "decorators": {"load": ["SELECT COUNT(*) AS schedule_)" +
                std::to_string(i % 2) + R"( FROM osquery_schedule"]}})"}});
    }
  };
  auto updater_a = std::async(std::launch::async, updates, "deadlock_a");
  auto updater_b = std::async(std::launch::async, updates, "deadlock_b");

  // Deadlocked threads cannot be joined, so report the failure and exit
  // instead of hanging the test run.
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(60);
  if (updater_a.wait_until(deadline) != std::future_status::ready ||
      updater_b.wait_until(deadline) != std::future_status::ready) {
    std::fprintf(stderr,
                 "Deadlock: concurrent config updates with a load decorator "
                 "reading osquery_schedule did not finish within 60 seconds\n");
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
  }
}

// An update's afterUpdate() runs only its own load decorators. If a newer
// update replaced them, the newer update runs its decorators itself, once its
// own changes, such as new ATC tables, have been applied.
TEST_F(DecoratorsConfigParserPluginTests,
       test_load_decorators_superseded_by_newer_update) {
  FLAGS_disable_decorators = false;
  const std::string source{"superseded_test"};
  auto parser = Config::getParser("decorators");
  ASSERT_NE(parser, nullptr);

  // Update A runs on its own thread, and B replaces its decorators before A's
  // afterUpdate() runs.
  std::promise<void> a_updated;
  std::promise<void> b_updated;
  std::thread update_a([&]() {
    parser->update(source, makeDecoratorsConfig("SELECT 'a' AS superseded"));
    a_updated.set_value();
    b_updated.get_future().wait();
    parser->afterUpdate();
  });
  a_updated.get_future().wait();
  parser->update(source, makeDecoratorsConfig("SELECT 'b' AS superseded"));
  b_updated.set_value();
  update_a.join();

  // A must not have run B's decorators, which may need B's changes.
  EXPECT_EQ(getDecoration("superseded"), "<missing>");

  parser->afterUpdate();
  EXPECT_EQ(getDecoration("superseded"), "b");

  parser->update(source, {});
  parser->afterUpdate();
}
} // namespace osquery
