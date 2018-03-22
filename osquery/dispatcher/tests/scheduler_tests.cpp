/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/dispatcher/scheduler.h"
#include "osquery/sql/sqlite_util.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_bool(disable_logging);
DECLARE_uint64(schedule_reload);

class SchedulerTests : public testing::Test {
  void SetUp() override {
    logging_ = FLAGS_disable_logging;
    FLAGS_disable_logging = true;
    Config::get().reset();
  }

  void TearDown() override {
    FLAGS_disable_logging = logging_;
    Config::get().reset();
  }

 private:
  bool logging_{false};
};

TEST_F(SchedulerTests, test_monitor) {
  std::string name{"pack_test_test_query"};

  // This query has never run so it will not have a timestamp.
  std::string timestamp;
  getDatabaseValue(kPersistentSettings, "timestamp." + name, timestamp);
  ASSERT_TRUE(timestamp.empty());

  // Fill in a scheduled query and execute it via the query monitor wrapper.
  ScheduledQuery query;
  query.interval = 10;
  query.splayed_interval = 11;
  query.query = "select * from time";
  auto results = monitor(name, query);
  EXPECT_EQ(results.rows().size(), 1U);

  // Ask the config instance for the monitored performance.
  QueryPerformance perf;
  Config::get().getPerformanceStats(
      name, ([&perf](const QueryPerformance& r) { perf = r; }));
  // Make sure it was recorded query ran.
  // There is no pack for this query within the config, that is fine as these
  // performance stats are tracked independently.
  EXPECT_EQ(perf.executions, 1U);
  EXPECT_GT(perf.output_size, 0U);

  // A bit more testing, potentially redundant, check the database results.
  // Since we are only monitoring, no 'actual' results are stored.
  std::string content;
  getDatabaseValue(kQueries, name, content);
  EXPECT_TRUE(content.empty());

  // Finally, make sure there is a recorded timestamp for the execution.
  // We are not concerned with the APPROX value, only that it was recorded.
  getDatabaseValue(kPersistentSettings, "timestamp." + name, timestamp);
  EXPECT_FALSE(timestamp.empty());
}

TEST_F(SchedulerTests, test_config_results_purge) {
  // Set a query time for now (time is only important relative to a week ago).
  auto query_time = osquery::getUnixTime();
  setDatabaseValue(
      kPersistentSettings, "timestamp.test_query", std::to_string(query_time));
  // Store a meaningless saved query interval splay.
  setDatabaseValue(kPersistentSettings, "interval.test_query", "11");
  // Store meaningless query differential results.
  setDatabaseValue(kQueries, "test_query", "{}");

  // We do not need "THE" config instance.
  // We only need to trigger a 'purge' event, this occurs when configuration
  // content is updated by a plugin or on load.
  Config::get().purge();

  // Nothing should have been purged.
  {
    std::string content;
    getDatabaseValue(kPersistentSettings, "timestamp.test_query", content);
    EXPECT_FALSE(content.empty());
  }

  {
    std::string content;
    getDatabaseValue(kPersistentSettings, "interval.test_query", content);
    EXPECT_FALSE(content.empty());
  }

  {
    std::string content;
    getDatabaseValue(kQueries, "test_query", content);
    EXPECT_FALSE(content.empty());
  }

  // Update the timestamp to have run a week and a day ago.
  query_time -= (84600 * (7 + 1));
  setDatabaseValue(
      kPersistentSettings, "timestamp.test_query", std::to_string(query_time));

  // Trigger another purge.
  Config::get().purge();
  // Now ALL 'test_query' related storage will have been purged.
  {
    std::string content;
    getDatabaseValue(kPersistentSettings, "timestamp.test_query", content);
    EXPECT_TRUE(content.empty());
  }

  {
    std::string content;
    getDatabaseValue(kPersistentSettings, "interval.test_query", content);
    EXPECT_TRUE(content.empty());
  }

  {
    std::string content;
    getDatabaseValue(kQueries, "test_query", content);
    EXPECT_TRUE(content.empty());
  }
}

TEST_F(SchedulerTests, test_scheduler) {
  auto backup_step = TablePlugin::kCacheStep;
  auto backup_interval = TablePlugin::kCacheInterval;

  // Start the scheduler now.
  auto now = osquery::getUnixTime();
  TablePlugin::kCacheStep = now;

  // Update the config with a pack/schedule that contains several queries.
  std::string config =
      "{"
      "\"packs\": {"
      "\"scheduler\": {"
      "\"queries\": {"
      "\"1\": {\"query\": \"select * from osquery_schedule\", \"interval\": 1},"
      "\"2\": {\"query\": \"select * from osquery_info\", \"interval\": 1},"
      "\"3\": {\"query\": \"select * from processes\", \"interval\": 1},"
      "\"4\": {\"query\": \"select * from osquery_packs\", \"interval\": 1}"
      "}"
      "}"
      "}"
      "}";
  Config::get().update({{"data", config}});

  // Run the scheduler for 1 second with a second interval.
  SchedulerRunner runner(static_cast<unsigned long int>(now + 1), 1);
  runner.start();

  // If a query was executed the cache step will have been advanced.
  EXPECT_GT(TablePlugin::kCacheStep, now);

  // Restore plugin settings.
  TablePlugin::kCacheStep = backup_step;
  TablePlugin::kCacheInterval = backup_interval;
}

TEST_F(SchedulerTests, test_scheduler_reload) {
  std::string config =
      "{\"schedule\":{\"1\":{"
      "\"query\":\"select * from processes\", \"interval\":1}}}";
  auto backup_reload = FLAGS_schedule_reload;

  // Start the scheduler;
  auto expire = static_cast<unsigned long int>(getUnixTime() + 1);
  FLAGS_schedule_reload = 1;
  SchedulerRunner runner(expire, 1);
  FLAGS_schedule_reload = backup_reload;
}
}
