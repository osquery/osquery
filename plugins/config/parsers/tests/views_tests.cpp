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
#include <vector>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/sqlite_util.h>

namespace osquery {

class ViewsConfigParserPluginTests : public testing::Test {
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

TEST_F(ViewsConfigParserPluginTests, test_add_view) {
  Config c;
  auto s = c.update(getTestConfigMap("test_parse_items.conf"));
  EXPECT_TRUE(s.ok());

  std::vector<std::string> old_views_vec;
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  c.reset();
}

TEST_F(ViewsConfigParserPluginTests, test_swap_view) {
  Config c;
  std::vector<std::string> old_views_vec;
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  old_views_vec.clear();
  auto s = c.update(getTestConfigMap("view_test.conf"));
  EXPECT_TRUE(s.ok());
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  EXPECT_EQ(old_views_vec[0], "config_views.kernel_hashes_new");

  c.reset();
}

TEST_F(ViewsConfigParserPluginTests, test_update_view) {
  Config c;
  std::vector<std::string> old_views_vec;
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  old_views_vec.clear();
  auto s = c.update(getTestConfigMap("view_test2.conf"));
  EXPECT_TRUE(s.ok());
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  std::string query;
  getDatabaseValue(kQueries, "config_views.kernel_hashes_new", query);
  EXPECT_EQ(query,
            "select hash.path as binary, version, hash.sha256 as SHA256, "
            "hash.sha1 as SHA1, hash.md5 as MD5 from (select path || "
            "'/Contents/MacOS/' as directory, name, version from "
            "kernel_extensions) join hash using (directory)");

  c.reset();
}

// Regression test for https://github.com/osquery/osquery/issues/9229.
//
// If the primary SQLite connection was busy during a config update, the view
// used to be created on a transient connection and lost when it closed.
TEST_F(ViewsConfigParserPluginTests, test_busy_connection_creates_view) {
  const std::string config1 = R"({"views": {"busy_view": "SELECT 1 AS one"}})";
  const std::string config2 =
      R"({"views": {"busy_view": "SELECT 1 AS one"}, "options": {}})";

  {
    auto busy = SQLiteDBManager::get(); // hold the primary connection
    ASSERT_TRUE(busy->isPrimary());
    ASSERT_TRUE(Config::get().update({{"views_busy", config1}}).ok());
  }

  QueryData r;
  auto s = query("SELECT * FROM busy_view", r);
  EXPECT_TRUE(s.ok());
  ASSERT_EQ(r.size(), 1U);
  EXPECT_EQ(r[0]["one"], "1");

  // A later update with the same view definition keeps it working and usable.
  ASSERT_TRUE(Config::get().update({{"views_busy", config2}}).ok());
  r.clear();
  s = query("SELECT * FROM busy_view", r);
  EXPECT_TRUE(s.ok());
  ASSERT_EQ(r.size(), 1U);
  EXPECT_EQ(r[0]["one"], "1");

  // Cleanup: tear down the view.
  const std::string config_empty = R"({"views": {}})";
  ASSERT_TRUE(Config::get().update({{"views_busy", config_empty}}).ok());
  r.clear();
  EXPECT_FALSE(query("SELECT * FROM busy_view", r).ok());
}

// A config update holds the config schedule lock while running the config
// parsers. Creating views on the primary connection takes the primary SQLite
// connection's attach lock. A query holds that attach lock while it runs, and
// osquery_schedule takes the config schedule lock to read the schedule.
// Running both at once must not deadlock.
TEST_F(ViewsConfigParserPluginTests, test_config_update_and_query_no_deadlock) {
  std::atomic<bool> stop{false};
  const std::string kConfigWithView = R"({
    "schedule": {"view_query": {"query": "SELECT 1", "interval": 60}},
    "views": {"deadlock_view": "SELECT 1 AS one"}
  })";
  const std::string kConfigWithoutView = R"({
    "schedule": {"view_query": {"query": "SELECT 1", "interval": 60}},
    "views": {}
  })";

  auto updater = std::async(
      std::launch::async, [&stop, &kConfigWithView, &kConfigWithoutView]() {
        for (size_t i = 0; i < 200 && !stop; ++i) {
          Config::get().update(
              {{"views_deadlock",
                (i % 2 == 0) ? kConfigWithView : kConfigWithoutView}});
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
      std::chrono::steady_clock::now() + std::chrono::seconds(60);
  if (updater.wait_until(deadline) != std::future_status::ready ||
      querier.wait_until(deadline) != std::future_status::ready) {
    std::fprintf(stderr,
                 "Deadlock: a config update and a query of osquery_schedule "
                 "did not finish within 60 seconds\n");
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
  }

  // Leave view dropped.
  Config::get().update({{"views_deadlock", kConfigWithoutView}});
}

} // namespace osquery
