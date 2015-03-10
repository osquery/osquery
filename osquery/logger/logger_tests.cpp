/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

DECLARE_string(logger_plugin);

class LoggerTests : public testing::Test {
 public:
  LoggerTests() {}

  void SetUp() {
    log_lines.clear();
    status_messages.clear();
    statuses_logged = 0;
    last_status = {O_INFO, "", -1, ""};
  }

  // Track lines emitted to logString
  static std::vector<std::string> log_lines;

  // Track the results of init
  static StatusLogLine last_status;
  static std::vector<std::string> status_messages;

  // Count calls to logStatus
  static int statuses_logged;
};

std::vector<std::string> LoggerTests::log_lines;
StatusLogLine LoggerTests::last_status;
std::vector<std::string> LoggerTests::status_messages;
int LoggerTests::statuses_logged = 0;

class TestLoggerPlugin : public LoggerPlugin {
 public:
  TestLoggerPlugin() {}

  Status logString(const std::string& s) {
    LoggerTests::log_lines.push_back(s);
    return Status(0, s);
  }

  Status init(const std::string& name, const std::vector<StatusLogLine>& log) {
    for (const auto& status : log) {
      LoggerTests::status_messages.push_back(status.message);
    }

    if (log.size() > 0) {
      LoggerTests::last_status = log.back();
    }

    if (name == "RETURN_FAILURE") {
      return Status(1, "OK");
    } else {
      return Status(0, "OK");
    }
  }

  Status logStatus(const std::vector<StatusLogLine>& log) {
    ++LoggerTests::statuses_logged;
    return Status(0, "OK");
  }

  virtual ~TestLoggerPlugin() {}
};

TEST_F(LoggerTests, test_plugin) {
  Registry::add<TestLoggerPlugin>("logger", "test");
  Registry::setUp();

  auto s = Registry::call("logger", "test", {{"string", "foobar"}});
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(LoggerTests::log_lines.back(), "foobar");
}

TEST_F(LoggerTests, test_logger_init) {
  // Expect the logger to have been registered from the first test.
  EXPECT_TRUE(Registry::exists("logger", "test"));
  EXPECT_TRUE(Registry::setActive("logger", "test").ok());

  initStatusLogger("logger_test");
  // This will be printed to stdout.
  LOG(WARNING) << "Logger test is generating a warning status (1)";
  initLogger("logger_test");

  // The warning message will have been buffered and sent to the active logger
  // which is test.
  EXPECT_EQ(LoggerTests::status_messages.size(), 1);

  // The logStatus API should NOT have been called. It will only be used if
  // (1) The active logger's init returns success within initLogger and
  // (2) for status logs generated after initLogger is called.
  EXPECT_EQ(LoggerTests::statuses_logged, 0);
}

TEST_F(LoggerTests, test_logger_log_status) {
  // This will be printed to stdout.
  LOG(WARNING) << "Logger test is generating a warning status (2)";

  // The second warning status will be sent to the logger plugin.
  EXPECT_EQ(LoggerTests::statuses_logged, 1);
}

TEST_F(LoggerTests, test_logger_variations) {
  // Init the logger for a second time, this should only be done for testing.
  // This time we'll trigger the init method to fail and prevent additional
  // status messages from trigger logStatus.
  initLogger("RETURN_FAILURE");

  // This will be printed to stdout.
  LOG(WARNING) << "Logger test is generating a warning status (3)";

  // Since the initLogger call triggered a failed init, meaning the logger
  // does NOT handle Glog logs, there will be no statuses logged.
  EXPECT_EQ(LoggerTests::statuses_logged, 0);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
