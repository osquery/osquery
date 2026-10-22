/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <string>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <plugins/config/parsers/decorators.h>

namespace osquery {

class ATCConfigParserPluginTests : public testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      initialized = true;
      platformSetup();
      registryAndPluginInit();
      initDatabasePluginForTesting();
    }
  }
};

namespace {

const std::string kSource{"atc_deadlock_test"};

// Both configs schedule a query, so osquery_schedule has rows to generate.
// Alternating between them makes every update attach or detach an ATC table.
// The ATC parser only detaches tables when the auto_table_construction key is
// present, so the second config sets it to an empty object.
const std::string kConfigWithTable = R"({
  "schedule": {"atc_query": {"query": "SELECT 1", "interval": 60}},
  "auto_table_construction": {
    "atc_deadlock_table": {
      "query": "SELECT value FROM test",
      "path": "/nonexistent/atc_deadlock.db",
      "columns": ["value"]
    }
  }
})";

const std::string kConfigWithoutTable = R"({
  "schedule": {"atc_query": {"query": "SELECT 1", "interval": 60}},
  "auto_table_construction": {}
})";

} // namespace

// Regression test for https://github.com/osquery/osquery/issues/8022.
//
// A config update holds the config schedule lock while running the config
// parsers. The ATC parser attaches and detaches tables, which takes the
// primary SQLite connection's attach lock. A query holds that attach lock while
// it runs, and osquery_schedule takes the config schedule lock to read the
// schedule. Running both at once used to deadlock.
TEST_F(ATCConfigParserPluginTests, test_config_update_and_query_no_deadlock) {
  std::atomic<bool> stop{false};

  auto updater = std::async(std::launch::async, [&stop]() {
    for (size_t i = 0; i < 200 && !stop; ++i) {
      Config::get().update(
          {{kSource, (i % 2 == 0) ? kConfigWithTable : kConfigWithoutTable}});
    }
    stop = true;
  });

  auto querier = std::async(std::launch::async, [&stop]() {
    while (!stop) {
      QueryData results;
      query("SELECT name FROM osquery_schedule", results);
    }
  });

  // Each thread waits on the other when deadlocked, so they cannot be joined
  // and the test cannot clean up. Report the failure and exit instead of
  // hanging the test run.
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(60);
  if (updater.wait_until(deadline) != std::future_status::ready ||
      querier.wait_until(deadline) != std::future_status::ready) {
    std::fprintf(stderr,
                 "Deadlock: a config update and a query of osquery_schedule "
                 "did not finish within 60 seconds\n");
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
  }

  // Leave the ATC table detached.
  Config::get().update({{kSource, kConfigWithoutTable}});
}

// Repeated updates must really attach and detach the table; otherwise the
// deadlock test above would not exercise the attach path.
TEST_F(ATCConfigParserPluginTests, test_table_attach_and_detach) {
  QueryData results;

  ASSERT_TRUE(Config::get().update({{kSource, kConfigWithTable}}).ok());
  EXPECT_TRUE(query("SELECT * FROM atc_deadlock_table", results).ok());

  ASSERT_TRUE(Config::get().update({{kSource, kConfigWithoutTable}}).ok());
  EXPECT_FALSE(query("SELECT * FROM atc_deadlock_table", results).ok());

  ASSERT_TRUE(Config::get().update({{kSource, kConfigWithTable}}).ok());
  EXPECT_TRUE(query("SELECT * FROM atc_deadlock_table", results).ok());

  ASSERT_TRUE(Config::get().update({{kSource, kConfigWithoutTable}}).ok());
}

namespace {

const std::string kDecoratorSource{"atc_decorator_test"};

// A config with an ATC table whose only column is `column`, and a load
// decorator that only succeeds against the table defined with column "other".
std::string configWithDecoratedTable(const std::string& column) {
  return R"({
    "auto_table_construction": {
      "atc_decorator_table": {
        "query": "SELECT )" +
         column + R"( FROM test",
        "path": "/nonexistent/atc_decorator.db",
        "columns": [")" +
         column + R"("]
      }
    },
    "decorators": {
      "load": ["SELECT COUNT(other) AS atc_load_test FROM atc_decorator_table"]
    }
  })";
}

std::string getLoadDecoration() {
  std::map<std::string, std::string> decorations;
  getDecorations(decorations);
  auto it = decorations.find("atc_load_test");
  return it == decorations.end() ? "<missing>" : it->second;
}

} // namespace

// Load decorators run after the ATC tables of the same config are attached,
// so they can query a table that the config adds.
TEST_F(ATCConfigParserPluginTests, test_load_decorator_sees_new_table) {
  ASSERT_TRUE(
      Config::get()
          .update({{kDecoratorSource, configWithDecoratedTable("other")}})
          .ok());
  EXPECT_EQ(getLoadDecoration(), "0");

  ASSERT_TRUE(
      Config::get().update({{kDecoratorSource, kConfigWithoutTable}}).ok());
  EXPECT_EQ(getLoadDecoration(), "<missing>");
}

// Load decorators see the new definition of a table that a refresh changes.
TEST_F(ATCConfigParserPluginTests, test_load_decorator_sees_changed_table) {
  // The decorator's column does not exist in this definition.
  ASSERT_TRUE(
      Config::get()
          .update({{kDecoratorSource, configWithDecoratedTable("value")}})
          .ok());
  EXPECT_EQ(getLoadDecoration(), "<missing>");

  ASSERT_TRUE(
      Config::get()
          .update({{kDecoratorSource, configWithDecoratedTable("other")}})
          .ok());
  EXPECT_EQ(getLoadDecoration(), "0");

  ASSERT_TRUE(
      Config::get().update({{kDecoratorSource, kConfigWithoutTable}}).ok());
}

// In a wildcard multi-pack, a pack's discovery query can use an ATC table that
// an earlier pack defines.
TEST_F(ATCConfigParserPluginTests, test_multi_pack_discovery_sees_table) {
  const std::string source{"atc_multi_pack_test"};
  const std::string config = R"({
    "packs": {
      "*": {
        "atc_defining_pack": {
          "auto_table_construction": {
            "atc_discovery_table": {
              "query": "SELECT value FROM test",
              "path": "/nonexistent/atc_discovery.db",
              "columns": ["value"]
            }
          },
          "queries": {"atc_defining_query": {"query": "SELECT 1", "interval": 60}}
        },
        "atc_discovering_pack": {
          "discovery": ["SELECT COUNT(*) FROM atc_discovery_table"],
          "queries": {"atc_discovered_query": {"query": "SELECT 1", "interval": 60}}
        }
      }
    }
  })";

  ASSERT_TRUE(Config::get().update({{source, config}}).ok());

  bool discovered = false;
  Config::get().scheduledQueries(
      [&discovered](const std::string& name, const ScheduledQuery&) {
        if (name.find("atc_discovered_query") != std::string::npos) {
          discovered = true;
        }
      });
  EXPECT_TRUE(discovered);

  ASSERT_TRUE(Config::get().update({{source, kConfigWithoutTable}}).ok());
}

} // namespace osquery
