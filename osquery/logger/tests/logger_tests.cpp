/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>

namespace osquery {

DECLARE_bool(logger_secondary_status_only);

class LoggerTests : public testing::Test {
 public:
  void SetUp() override {
    // Backup the logging status, then disable.
    logging_status_ = FLAGS_disable_logging;
    FLAGS_disable_logging = false;

    // Setup / initialize static members.
    log_lines.clear();
    status_messages.clear();
    statuses_logged = 0;
    last_status = {O_INFO, "", -1, ""};
  }

  void TearDown() override {
    FLAGS_disable_logging = logging_status_;
  }

  // Track lines emitted to logString
  static std::vector<std::string> log_lines;

  // Track the results of init
  static StatusLogLine last_status;
  static std::vector<std::string> status_messages;

  // Count calls to logStatus
  static size_t statuses_logged;
  static size_t events_logged;
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
size_t LoggerTests::events_logged = 0;
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

  bool usesLogEvent() override {
    return shouldLogEvent;
  }

  Status logEvent(const std::string& e) override {
    LoggerTests::events_logged++;
    return Status(0, "OK");
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

  /// Allow test methods to change event logging state.
  bool shouldLogEvent{true};
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
  // This will be printed to stdout.
  LOG(WARNING) << "Logger test is generating a warning status (2)";

  // The second warning status will be sent to the logger plugin.
  EXPECT_EQ(1U, LoggerTests::statuses_logged);
}

TEST_F(LoggerTests, test_feature_request) {
  // Retrieve the test logger plugin.
  auto plugin = RegistryFactory::get().plugin("logger", "test");
  auto logger = std::dynamic_pointer_cast<TestLoggerPlugin>(plugin);

  logger->shouldLogEvent = false;
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
  rf.registry("logger")->add("second_test",
                             std::make_shared<SecondTestLoggerPlugin>());
  EXPECT_TRUE(rf.setActive("logger", "test,second_test").ok());

  // With two active loggers, the string should be added twice.
  logString("this is a test", "added");
  EXPECT_EQ(2U, LoggerTests::log_lines.size());

  LOG(WARNING) << "Logger test is generating a warning status (4)";
  // Refer to the above notes about status logs not emitting until the logger
  // it initialized. We do a 0-test to check for dead locks around attempting
  // to forward Glog-based sinks recursively into our sinks.
  EXPECT_EQ(0U, LoggerTests::statuses_logged);

  // Now try to initialize multiple loggers (1) forwards, (2) does not.
  // rf.setActive("logger", "test,second_test");
  initLogger("logger_test");
  LOG(WARNING) << "Logger test is generating a warning status (5)";
  // Now that the "test" logger is initialized, the status log will be
  // forwarded.
  EXPECT_EQ(2U, LoggerTests::statuses_logged);

  // Multiple logger plugins have a 'primary' concept.
  auto flag_default = FLAGS_logger_secondary_status_only;
  FLAGS_logger_secondary_status_only = true;
  logString("this is another test", "added");
  // Only one log line will be appended since 'second_test' is secondary.
  EXPECT_EQ(3U, LoggerTests::log_lines.size());
  // However, again, 2 status lines will be forwarded.
  LOG(WARNING) << "Logger test is generating another warning (6)";
  EXPECT_EQ(4U, LoggerTests::statuses_logged);
  FLAGS_logger_secondary_status_only = flag_default;
  logString("this is a third test", "added");
  EXPECT_EQ(5U, LoggerTests::log_lines.size());
}

TEST_F(LoggerTests, test_logger_scheduled_query) {
  RegistryFactory::get().setActive("logger", "test");

  QueryLogItem item;
  item.name = "test_query";
  item.identifier = "unknown_test_host";
  item.time = 0;
  item.calendar_time = "no_time";
  item.results.added.push_back({{"test_column", "test_value"}});
  logQueryLogItem(item);
  EXPECT_EQ(1U, LoggerTests::log_lines.size());

  item.results.removed.push_back({{"test_column", "test_new_value\n"}});
  logQueryLogItem(item);
  ASSERT_EQ(3U, LoggerTests::log_lines.size());

  // Make sure the JSON output does not have a newline.
  std::string expected =
      "{\"name\":\"test_query\",\"hostIdentifier\":\"unknown_test_host\","
      "\"calendarTime\":\"no_time\",\"unixTime\":\"0\",\"columns\":{\"test_"
      "column\":\"test_value\"},\"action\":\"added\"}";
  EXPECT_EQ(LoggerTests::log_lines.back(), expected);
}
}
