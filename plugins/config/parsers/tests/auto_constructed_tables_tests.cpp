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

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  if (updater.wait_until(deadline) != std::future_status::ready ||
      querier.wait_until(deadline) != std::future_status::ready) {
    std::fprintf(stderr,
                 "Deadlock: a config update and a query of osquery_schedule "
                 "did not finish within 5 seconds\n");
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
  }

  Config::get().update({{kSource, kConfigWithoutTable}});
}

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

} // namespace osquery
