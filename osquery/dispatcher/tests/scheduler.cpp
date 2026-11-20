/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/dispatcher/scheduler.h>
#include <osquery/logger/logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/numeric_monitoring/plugin_interface.h>
#include <osquery/registry/registry.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/utils/system/time.h>

namespace osquery {

DECLARE_bool(disable_logging);
DECLARE_bool(enable_numeric_monitoring);
DECLARE_uint64(schedule_reload);
DECLARE_string(numeric_monitoring_plugins);
DECLARE_uint64(numeric_monitoring_pre_aggregation_time);

namespace {
const auto kRowsMetricPluginName = "scheduler_rows_test_plugin";
}

class SchedulerRowsTestPlugin : public NumericMonitoringPlugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) override {
    points.push_back(request);
    return Status::success();
  }

  static std::vector<PluginRequest> points;
};

std::vector<PluginRequest> SchedulerRowsTestPlugin::points;

REGISTER(SchedulerRowsTestPlugin,
         monitoring::registryName(),
         kRowsMetricPluginName);

class SchedulerTests : public testing::Test {
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    logging_ = FLAGS_disable_logging;
    FLAGS_disable_logging = true;
    Config::get().reset();
  }

  void TearDown() override {
    FLAGS_disable_logging = logging_;
    Config::get().reset();
    resetShutdown();
  }

 private:
  bool logging_{false};
};

TEST_F(SchedulerTests, test_monitor) {
  std::string name = "pack_test_test_query";

  // This query has never run so it will not have a timestamp.
  std::string timestamp;
  getDatabaseValue(kPersistentSettings, "timestamp." + name, timestamp);
  ASSERT_TRUE(timestamp.empty());

  // Fill in a scheduled query and execute it via the query monitor wrapper.
  ScheduledQuery query("time_pack", "time", "select * from time");
  query.interval = 10;
  query.splayed_interval = 11;

  auto results = monitor(name, query);
  EXPECT_EQ(results.rowsTyped().size(), 1U);

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

// Numeric monitoring profiles a query in addition to, not instead of, recording
// its performance, which osquery_schedule reports.
TEST_F(SchedulerTests, test_monitor_with_numeric_monitoring) {
  const auto numeric_monitoring = FLAGS_enable_numeric_monitoring;
  FLAGS_enable_numeric_monitoring = true;

  std::string name = "pack_test_numeric_monitoring_query";
  ScheduledQuery query("test", "test", "select 1 as number");
  query.interval = 10;
  query.splayed_interval = 11;

  auto results = monitor(name, query);
  EXPECT_EQ(results.rowsTyped().size(), 1U);
  results = monitor(name, query);
  EXPECT_EQ(results.rowsTyped().size(), 1U);

  QueryPerformance perf;
  Config::get().getPerformanceStats(
      name, ([&perf](const QueryPerformance& r) { perf = r; }));
  EXPECT_EQ(perf.executions, 2U);
  EXPECT_GT(perf.last_executed, 0U);
  EXPECT_EQ(perf.output_size, 28U);

  // The execution is recorded too, as without numeric monitoring.
  std::string timestamp;
  getDatabaseValue(kPersistentSettings, "timestamp." + name, timestamp);
  EXPECT_FALSE(timestamp.empty());

  FLAGS_enable_numeric_monitoring = numeric_monitoring;

  // Recording numeric monitoring points starts a flusher service; stop it so
  // the test does not leave a running thread behind. Stopping services leaves
  // the dispatcher refusing new services until it is reset.
  Dispatcher::stopServices();
  Dispatcher::joinServices();
  Dispatcher::instance().resetStopping();
}

TEST_F(SchedulerTests, test_rows_metric) {
  const auto numeric_monitoring = FLAGS_enable_numeric_monitoring;
  const auto plugins = FLAGS_numeric_monitoring_plugins;
  const auto pre_aggregation_time =
      FLAGS_numeric_monitoring_pre_aggregation_time;

  FLAGS_enable_numeric_monitoring = true;
  FLAGS_numeric_monitoring_plugins = kRowsMetricPluginName;
  FLAGS_numeric_monitoring_pre_aggregation_time = 0;

  ASSERT_TRUE(RegistryFactory::get()
                  .setActive(monitoring::registryName(),
                             FLAGS_numeric_monitoring_plugins)
                  .ok());

  monitoring::flush();
  SchedulerRowsTestPlugin::points.clear();

  std::string name = "pack_test_rows_metric_query";
  ScheduledQuery query("test_pack",
                       "test_query",
                       "select 1 as number union all select 2 as number");
  query.interval = 10;

  // The first execution emits both rows as added; the second has no
  // differential and emits nothing.
  ASSERT_TRUE(launchQuery(name, query).ok());
  ASSERT_TRUE(launchQuery(name, query).ok());

  const auto expected_path = "scheduler.query.test_pack.test_query.rows";
  std::vector<PluginRequest> rows_points;
  for (const auto& point : SchedulerRowsTestPlugin::points) {
    if (point.at(monitoring::recordKeys().path) == expected_path) {
      rows_points.push_back(point);
    }
  }
  ASSERT_EQ(rows_points.size(), 1U);
  EXPECT_EQ(rows_points.front().at(monitoring::recordKeys().value), "2");

  FLAGS_enable_numeric_monitoring = numeric_monitoring;
  FLAGS_numeric_monitoring_plugins = plugins;
  FLAGS_numeric_monitoring_pre_aggregation_time = pre_aggregation_time;

  Dispatcher::stopServices();
  Dispatcher::joinServices();
  Dispatcher::instance().resetStopping();
}

TEST_F(SchedulerTests, test_output_size) {
  // set up the test query
  auto query_name = "output_size_test_query";
  ScheduledQuery query("test", "test", "select 1 as number");
  query.interval = 1;
  query.splayed_interval = 0;

  auto results = monitor(query_name, query);
  EXPECT_EQ(results.rowsTyped().size(), 1U);

  QueryPerformance perf;
  Config::get().getPerformanceStats(
      query_name, ([&perf](const QueryPerformance& r) { perf = r; }));
  // Total execution should be just 1
  EXPECT_EQ(perf.executions, 1U);
  // The output size is 6 for "number", and 8 for the number, so 14 total
  EXPECT_EQ(perf.output_size, 14U);

  // run the query again
  results = monitor(query_name, query);
  EXPECT_EQ(results.rowsTyped().size(), 1U);

  Config::get().getPerformanceStats(
      query_name, ([&perf](const QueryPerformance& r) { perf = r; }));

  // this time check that executions and output_size are doubled
  EXPECT_EQ(perf.executions, 2U);
  EXPECT_EQ(perf.output_size, 28U);
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
  setDatabaseValue(kQueries, "test_querycounter", "1");
  setDatabaseValue(kQueries, "query.test_query", "SELECT * FROM TIME");

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

  // Reserved keys should not have a set timestamp
  {
    std::string content;
    getDatabaseValue(
        kPersistentSettings, "timestamp.test_querycounter", content);
    EXPECT_TRUE(content.empty());
  }

  {
    std::string content;
    getDatabaseValue(
        kPersistentSettings, "timestamp.query.test_query", content);
    EXPECT_TRUE(content.empty());
  }

  // Update the timestamp to have run a week and a day ago.
  query_time -= (86400 * (7 + 1));
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
  SchedulerRunner runner(static_cast<unsigned long int>(1), 1);
  runner.start();

  // If a query was executed the cache step will have been advanced.
  EXPECT_GT(TablePlugin::kCacheStep, now);

  // Restore plugin settings.
  TablePlugin::kCacheStep = backup_step;
  TablePlugin::kCacheInterval = backup_interval;
}

TEST_F(SchedulerTests, test_scheduler_zero_drift) {
  const auto backup_step = TablePlugin::kCacheStep;
  const auto backup_interval = TablePlugin::kCacheInterval;

  // Start the scheduler now.
  const auto now = osquery::getUnixTime();
  TablePlugin::kCacheStep = now;

  // Update the config with a pack/schedule that contains several queries.
  std::string config = R"config(
  {
    "packs": {
      "scheduler": {
        "queries": {
          "1": {"query": "select 1 as number", "interval": 1},
          "2": {"query": "select 2 as number", "interval": 1}
        }
      }
    }
  })config";
  Config::get().update({{"data", config}});

  // Run the scheduler for 1 second with a second interval.
  SchedulerRunner runner(
      static_cast<unsigned long int>(1), size_t{1}, std::chrono::seconds{10});
  runner.start();

  EXPECT_EQ(runner.getCurrentTimeDrift(), std::chrono::milliseconds::zero());

  // Restore plugin settings.
  TablePlugin::kCacheStep = backup_step;
  TablePlugin::kCacheInterval = backup_interval;
}

TEST_F(SchedulerTests, test_scheduler_drift_accumulation) {
  const auto backup_step = TablePlugin::kCacheStep;
  const auto backup_interval = TablePlugin::kCacheInterval;

  // Start the scheduler now.
  const auto now = osquery::getUnixTime();
  TablePlugin::kCacheStep = now;

  // Update the config with a pack/schedule that contains several queries.
  std::string config = R"config(
  {
    "packs": {
      "scheduler": {
        "queries": {
          "3": {"query": "select 3 as number", "interval": 1},
          "4": {"query": "select 4 as number", "interval": 1},
          "5": {"query": "select 5 as number", "interval": 1},
          "6": {"query": "select 6 as number", "interval": 1},
          "7": {"query": "select 7 as number", "interval": 1},
          "8": {"query": "select 1 as number", "interval": 1},
          "9": {"query": "select 2 as number", "interval": 1},
          "10": {"query": "select sleep(1)", "interval": 1}
        }
      }
    }
  })config";
  Config::get().update({{"data", config}});

  // Run the scheduler for 3 seconds with no interval.
  SchedulerRunner runner(
      static_cast<unsigned long int>(3), size_t{0}, std::chrono::seconds{10});
  runner.start();

  EXPECT_GE(runner.getCurrentTimeDrift(), std::chrono::milliseconds{1});

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
  auto expire = static_cast<unsigned long int>(1);
  FLAGS_schedule_reload = 1;
  SchedulerRunner runner(expire, 1);
  FLAGS_schedule_reload = backup_reload;
}
} // namespace osquery
