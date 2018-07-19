/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <thread>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

DECLARE_int32(minloglevel);
DECLARE_int32(stderrthreshold);

namespace osquery {

DECLARE_int32(logger_min_status);
DECLARE_bool(logger_secondary_status_only);
DECLARE_bool(logger_status_sync);
DECLARE_bool(logger_event_type);
DECLARE_bool(logger_snapshot_event_type);
DECLARE_bool(disable_logging);

class LoggerTests : public testing::Test {
 public:
  void SetUp() override {
    // Backup the logging status, then disable.
    logging_status_ = FLAGS_disable_logging;
    FLAGS_disable_logging = false;
    FLAGS_logger_status_sync = true;

    // Setup / initialize static members.
    log_lines.clear();
    status_messages.clear();
    statuses_logged = 0;
    last_status = {O_INFO, "", 10, "", "cal_time", 0, "host"};
  }

  void TearDown() override {
    FLAGS_disable_logging = logging_status_;
    FLAGS_logger_status_sync = false;
  }

  // Track lines emitted to logString
  static std::vector<std::string> log_lines;

  // Track the results of init
  static StatusLogLine last_status;
  static std::vector<std::string> status_messages;

  // Count calls to logStatus
  static size_t statuses_logged;
  // Count added and removed snapshot rows
  static size_t snapshot_rows_added;
  static size_t snapshot_rows_removed;

 private:
  /// Save the status of logging before running tests, restore afterward.
  bool logging_status_{true};
};

std::vector<std::string> LoggerTests::log_lines;
StatusLogLine LoggerTests::last_status;
std::vector<std::string> LoggerTests::status_messages;
size_t LoggerTests::statuses_logged = 0;
size_t LoggerTests::snapshot_rows_added = 0;
size_t LoggerTests::snapshot_rows_removed = 0;

inline void placeStatuses(const std::vector<StatusLogLine>& log) {
  for (const auto& status : log) {
    LoggerTests::status_messages.push_back(status.message);
  }

  LoggerTests::statuses_logged += log.size();
  if (log.size() > 0) {
    LoggerTests::last_status = log.back();
  }
}

class TestLoggerPlugin : public LoggerPlugin {
 protected:
  bool usesLogStatus() override {
    return shouldLogStatus;
  }

  Status logString(const std::string& s) override {
    LoggerTests::log_lines.push_back(s);
    return Status(0, s);
  }

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override {
    placeStatuses(log);
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    placeStatuses(log);
    return Status(0, "OK");
  }

  Status logSnapshot(const std::string& s) override {
    LoggerTests::snapshot_rows_added += 1;
    LoggerTests::snapshot_rows_removed += 0;
    return Status(0, "OK");
  }

 public:
  /// Allow test methods to change status logging state.
  bool shouldLogStatus{true};
};

TEST_F(LoggerTests, test_plugin) {
  auto& rf = RegistryFactory::get();
  rf.registry("logger")->add("test", std::make_shared<TestLoggerPlugin>());
  rf.setUp();

  auto s = Registry::call("logger", "test", {{"string", "foobar"}});
  EXPECT_TRUE(s.ok());
  EXPECT_EQ("foobar", LoggerTests::log_lines.back());
}

TEST_F(LoggerTests, test_logger_init) {
  auto& rf = RegistryFactory::get();
  // Expect the logger to have been registered from the first test.
  EXPECT_TRUE(rf.exists("logger", "test"));
  EXPECT_TRUE(rf.setActive("logger", "test").ok());

  initStatusLogger("logger_test");
  // This will be printed to stdout.
  LOG(WARNING) << "Logger test is generating a warning status (1)";
  initLogger("logger_test");

  // The warning message will have been buffered and sent to the active logger
  // which is test.
  EXPECT_EQ(1U, LoggerTests::status_messages.size());
  EXPECT_EQ(1U, LoggerTests::statuses_logged);
}

TEST_F(LoggerTests, test_log_string) {
  // So far, tests have only used the logger registry/plugin API.
  EXPECT_TRUE(logString("{\"json\": true}", "event"));
  ASSERT_EQ(1U, LoggerTests::log_lines.size());
  EXPECT_EQ("{\"json\": true}", LoggerTests::log_lines.back());

  // Expect the logString method to fail if we explicitly request a logger
  // plugin that has not been added to the registry.
  EXPECT_FALSE(logString("{\"json\": true}", "event", "does_not_exist"));

  // Expect the plugin not to receive logs if status logging is disabled.
  FLAGS_disable_logging = true;
  EXPECT_TRUE(logString("test", "event"));
  EXPECT_EQ(1U, LoggerTests::log_lines.size());
  FLAGS_disable_logging = false;

  // If logging is re-enabled, logs should send as usual.
  EXPECT_TRUE(logString("test", "event"));
  EXPECT_EQ(2U, LoggerTests::log_lines.size());
}

TEST_F(LoggerTests, test_logger_log_status) {
  std::string warning = "Logger test is generating a warning status (2)";
  auto now = getUnixTime();
  // This will be printed to stdout.
  LOG(WARNING) << warning;

  // The second warning status will be sent to the logger plugin.
  EXPECT_EQ(1U, LoggerTests::statuses_logged);

  EXPECT_EQ(O_WARNING, LoggerTests::last_status.severity);
  EXPECT_GT(LoggerTests::last_status.line, 0U);
  EXPECT_EQ(warning, LoggerTests::last_status.message);
  EXPECT_GE(now, LoggerTests::last_status.time);
  EXPECT_EQ(getHostIdentifier(), LoggerTests::last_status.identifier);
}

TEST_F(LoggerTests, test_logger_status_level) {
  auto minloglevel = FLAGS_minloglevel;
  FLAGS_minloglevel = 0;
  // This will be printed to stdout.
  LOG(INFO) << "Logger test is generating an info status";
  EXPECT_EQ(1U, LoggerTests::statuses_logged);

  FLAGS_minloglevel = 1;
  setVerboseLevel();

  LOG(INFO) << "Logger test is generating an info status";
  EXPECT_EQ(1U, LoggerTests::statuses_logged);
  LOG(WARNING) << "Logger test is generating a warning status";
  EXPECT_EQ(2U, LoggerTests::statuses_logged);
  FLAGS_minloglevel = minloglevel;

  auto stderrthreshold = FLAGS_stderrthreshold;
  FLAGS_stderrthreshold = 2;
  setVerboseLevel();

  LOG(WARNING) << "Logger test is generating a warning status";
  EXPECT_EQ(3U, LoggerTests::statuses_logged);
  FLAGS_stderrthreshold = stderrthreshold;

  auto logger_min_status = FLAGS_logger_min_status;
  FLAGS_logger_min_status = 1;
  setVerboseLevel();

  LOG(INFO) << "Logger test is generating an info status";
  EXPECT_EQ(3U, LoggerTests::statuses_logged);
  LOG(WARNING) << "Logger test is generating a warning status";
  EXPECT_EQ(4U, LoggerTests::statuses_logged);
  FLAGS_logger_min_status = logger_min_status;
}

TEST_F(LoggerTests, test_feature_request) {
  // Retrieve the test logger plugin.
  auto plugin = RegistryFactory::get().plugin("logger", "test");
  auto logger = std::dynamic_pointer_cast<TestLoggerPlugin>(plugin);

  logger->shouldLogStatus = false;
  auto status = Registry::call("logger", "test", {{"action", "features"}});
  EXPECT_EQ(0, status.getCode());

  logger->shouldLogStatus = true;
  status = Registry::call("logger", "test", {{"action", "features"}});
  EXPECT_EQ(LOGGER_FEATURE_LOGSTATUS, status.getCode());
}

TEST_F(LoggerTests, test_logger_variations) {
  // Retrieve the test logger plugin.
  auto plugin = RegistryFactory::get().plugin("logger", "test");
  auto logger = std::dynamic_pointer_cast<TestLoggerPlugin>(plugin);
  // Change the behavior.
  logger->shouldLogStatus = false;

  // Call the logger initialization again, then reset the behavior.
  initLogger("duplicate_logger");
  logger->shouldLogStatus = true;

  // This will be printed to stdout.
  LOG(WARNING) << "Logger test is generating a warning status (3)";

  // Since the initLogger call triggered a failed init, meaning the logger
  // does NOT handle Glog logs, there will be no statuses logged.
  EXPECT_EQ(0U, LoggerTests::statuses_logged);
}

TEST_F(LoggerTests, test_logger_snapshots) {
  // A snapshot query should not include removed items.
  QueryLogItem item;
  item.name = "test_query";
  item.identifier = "unknown_test_host";
  item.time = 0;
  item.calendar_time = "no_time";

  // Add a fake set of results.
  item.results.added.push_back({{"test_column", "test_value"}});
  logSnapshotQuery(item);

  // Expect the plugin to optionally handle snapshot logging.
  EXPECT_EQ(1U, LoggerTests::snapshot_rows_added);

  // Expect a single event, event though there were two added.
  item.results.added.push_back({{"test_column", "test_value"}});
  logSnapshotQuery(item);
  EXPECT_EQ(2U, LoggerTests::snapshot_rows_added);

  FLAGS_logger_snapshot_event_type = true;
  logSnapshotQuery(item);
  EXPECT_EQ(4U, LoggerTests::snapshot_rows_added);
  FLAGS_logger_snapshot_event_type = false;
}

class SecondTestLoggerPlugin : public LoggerPlugin {
 public:
  Status logString(const std::string& s) override {
    LoggerTests::log_lines.push_back(s);
    return Status(0);
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    placeStatuses(log);
    return Status(0, "OK");
  }

  bool usesLogStatus() override {
    return true;
  }

 protected:
  void init(const std::string& binary_name,
            const std::vector<StatusLogLine>& log) override {
    placeStatuses(log);
  }
};

TEST_F(LoggerTests, test_multiple_loggers) {
  auto& rf = RegistryFactory::get();
  auto second = std::make_shared<SecondTestLoggerPlugin>();
  rf.registry("logger")->add("second_test", second);
  EXPECT_TRUE(rf.setActive("logger", "test,second_test").ok());

  auto test_plugin = rf.registry("logger")->plugin("test");
  auto test_logger = std::dynamic_pointer_cast<TestLoggerPlugin>(test_plugin);
  test_logger->shouldLogStatus = false;

  // With two active loggers, the string should be added twice.
  logString("this is a test", "added");
  EXPECT_EQ(2U, LoggerTests::log_lines.size());

  LOG(WARNING) << "Logger test is generating a warning status (4)";
  // Refer to the above notes about status logs not emitting until the logger
  // it initialized. We do a 0-test to check for dead locks around attempting
  // to forward Glog-based sinks recursively into our sinks.
  EXPECT_EQ(0U, LoggerTests::statuses_logged);

  // Now try to initialize multiple loggers (1) forwards, (2) does not.
  initLogger("logger_test");
  LOG(WARNING) << "Logger test is generating a warning status (5)";
  // Now that the "test" logger is initialized, the status log will be
  // forwarded.
  EXPECT_EQ(1U, LoggerTests::statuses_logged);

  // Multiple logger plugins have a 'primary' concept.
  auto flag_default = FLAGS_logger_secondary_status_only;
  FLAGS_logger_secondary_status_only = true;
  logString("this is another test", "added");
  // Only one log line will be appended since 'second_test' is secondary.
  EXPECT_EQ(3U, LoggerTests::log_lines.size());
  // Only one status line will be forwarded.
  LOG(WARNING) << "Logger test is generating another warning (6)";
  EXPECT_EQ(2U, LoggerTests::statuses_logged);
  FLAGS_logger_secondary_status_only = flag_default;
  logString("this is a third test", "added");
  EXPECT_EQ(5U, LoggerTests::log_lines.size());

  // Reconfigure the second logger to forward status logs.
  test_logger->shouldLogStatus = true;
  initLogger("logger_test");
  LOG(WARNING) << "Logger test is generating another warning (7)";
  EXPECT_EQ(4U, LoggerTests::statuses_logged);
}

TEST_F(LoggerTests, test_logger_scheduled_query) {
  RegistryFactory::get().setActive("logger", "test");
  initLogger("scheduled_query");

  QueryLogItem item;
  item.name = "test_query";
  item.identifier = "unknown_test_host";
  item.time = 0;
  item.calendar_time = "no_time";
  item.epoch = 0L;
  item.counter = 0L;
  item.results.added.push_back({{"test_column", "test_value"}});
  logQueryLogItem(item);
  EXPECT_EQ(1U, LoggerTests::log_lines.size());

  // The entire removed/added is one event when result events is false.
  FLAGS_logger_event_type = false;
  item.results.removed.push_back({{"test_column", "test_new_value\n"}});
  logQueryLogItem(item);
  EXPECT_EQ(2U, LoggerTests::log_lines.size());
  FLAGS_logger_event_type = true;

  // Now the two removed will be individual events.
  logQueryLogItem(item);
  ASSERT_EQ(4U, LoggerTests::log_lines.size());

  // Make sure the JSON output does not have a newline.
  std::string expected =
      "{\"name\":\"test_query\",\"hostIdentifier\":\"unknown_test_host\","
      "\"calendarTime\":\"no_time\",\"unixTime\":0,\"epoch\":0,"
      "\"counter\":0,\"columns\":{\"test_column\":\"test_value\"},"
      "\"action\":\"added\"}";
  EXPECT_EQ(LoggerTests::log_lines.back(), expected);
}

class RecursiveLoggerPlugin : public LoggerPlugin {
 protected:
  bool usesLogStatus() override {
    return true;
  }

  Status logString(const std::string& s) override {
    return Status(0, s);
  }

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override {
    logStatus(log);
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    for (const auto& item : log) {
      if (item.message == "recurse") {
        LOG(WARNING) << "Logging a status withing a status logger";
      }
      statuses++;
    }
    return Status(0, "OK");
  }

  Status logSnapshot(const std::string& s) override {
    return Status(0, "OK");
  }

 public:
  size_t statuses{0};
};

TEST_F(LoggerTests, test_recursion) {
  // Stop the internal Glog facilities.
  google::ShutdownGoogleLogging();

  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<RecursiveLoggerPlugin>();
  rf.registry("logger")->add("recurse", plugin);
  EXPECT_TRUE(rf.exists("logger", "recurse"));
  EXPECT_TRUE(rf.setActive("logger", "recurse").ok());

  FLAGS_logtostderr = true;
  initStatusLogger("logger_test");
  initLogger("logger_test");
  LOG(WARNING) << "Log to the recursive logger";
  EXPECT_EQ(1U, plugin->statuses);

  FLAGS_logger_status_sync = false;
  LOG(WARNING) << "recurse";
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    for (size_t i = 0; i < 100; i++) {
      std::this_thread::sleep_for(std::chrono::microseconds(10));
      if (plugin->statuses == 3U) {
        break;
      }
    }
  }
  EXPECT_EQ(3U, plugin->statuses);

  // Try again with the tool type as a daemon.
  auto tool_type = kToolType;
  kToolType = ToolType::DAEMON;
  LOG(WARNING) << "recurse";

  // The daemon calls the status relay within the scheduler.
  EXPECT_EQ(3U, plugin->statuses);

  // All of recursive log lines will sink during the next call.
  relayStatusLogs(true);
  EXPECT_EQ(4U, plugin->statuses);
  relayStatusLogs(true);
  EXPECT_EQ(5U, plugin->statuses);
  kToolType = tool_type;

  EXPECT_EQ(0U, queuedStatuses());
  EXPECT_EQ(0U, queuedSenders());

  // Make sure the test file does not create a filesystem log.
  // This will happen if the logtostderr is not set.
  EXPECT_FALSE(pathExists("logger_test.INFO"));

  FLAGS_logtostderr = false;
}
}
