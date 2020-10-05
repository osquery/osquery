/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_interface.h>

#include "plugins/logger/buffered.h"
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

using namespace testing;
namespace pt = boost::property_tree;

namespace osquery {

DECLARE_uint64(buffered_log_max);

// Check that the string matches the StatusLogLine
MATCHER_P(MatchesStatus, expected, "") {
  pt::ptree actual;
  std::stringstream json_in(arg);
  try {
    pt::read_json(json_in, actual);
    return expected.severity == actual.get<int>("severity") &&
           expected.filename == actual.get<std::string>("filename") &&
           expected.line == actual.get<size_t>("line") &&
           expected.message == actual.get<std::string>("message");
  } catch (const std::exception& /* e */) {
    return false;
  }
}

class BufferedLogForwarderTests : public Test {
 protected:
  void SetUp() {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }

 public:
  const std::chrono::milliseconds kLogPeriod = std::chrono::milliseconds(100);

  StatusLogLine makeStatusLogLine(StatusLogSeverity severity,
                                  const std::string& filename,
                                  int line,
                                  const std::string& message) {
    StatusLogLine log;
    log.severity = severity;
    log.filename = filename;
    log.line = line;
    log.message = message;
    return log;
  }
};

class MockBufferedLogForwarder : public BufferedLogForwarder {
 public:
  MockBufferedLogForwarder(
      const std::string& name = "mock",
      const std::chrono::duration<long, std::ratio<1, 1000>> log_period =
          kLogPeriod,
      size_t max_log_lines = kMaxLogLines)
      : BufferedLogForwarder(
            "MockBufferedLogForwarder", name, log_period, max_log_lines) {}

  bool interrupted() {
    // A small conditional to force-skip an interruption check, used in testing.
    if (!checked_) {
      checked_ = true;
      return false;
    } else {
      return BufferedLogForwarder::interrupted();
    }
  }

  MOCK_METHOD2(send,
               Status(std::vector<std::string>& log_data,
                      const std::string& log_type));
  FRIEND_TEST(BufferedLogForwarderTests, test_index);
  FRIEND_TEST(BufferedLogForwarderTests, test_basic);
  FRIEND_TEST(BufferedLogForwarderTests, test_retry);
  FRIEND_TEST(BufferedLogForwarderTests, test_multiple);
  FRIEND_TEST(BufferedLogForwarderTests, test_async);
  FRIEND_TEST(BufferedLogForwarderTests, test_split);
  FRIEND_TEST(BufferedLogForwarderTests, test_purge);
  FRIEND_TEST(BufferedLogForwarderTests, test_purge_max);

 private:
  bool checked_{false};
};

TEST_F(BufferedLogForwarderTests, test_index) {
  MockBufferedLogForwarder runner;
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_THAT(runner.genResultIndex(), ContainsRegex("mock_r_[0-9]+_1"));
    EXPECT_THAT(runner.genStatusIndex(), ContainsRegex("mock_s_[0-9]+_2"));
    EXPECT_THAT(runner.genResultIndex(), ContainsRegex("mock_r_[0-9]+_3"));
    EXPECT_THAT(runner.genStatusIndex(), ContainsRegex("mock_s_[0-9]+_4"));
  }

  EXPECT_TRUE(runner.isResultIndex(runner.genResultIndex()));
  EXPECT_FALSE(runner.isResultIndex(runner.genStatusIndex()));
  EXPECT_FALSE(runner.isResultIndex("foo"));

  EXPECT_TRUE(runner.isStatusIndex(runner.genStatusIndex()));
  EXPECT_FALSE(runner.isStatusIndex(runner.genResultIndex()));
  EXPECT_FALSE(runner.isStatusIndex("foo"));
}

TEST_F(BufferedLogForwarderTests, test_basic) {
  StrictMock<MockBufferedLogForwarder> runner;
  runner.logString("foo");

  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0)));
  runner.check();
  // This call should not result in sending again
  runner.check();

  StatusLogLine log1 = makeStatusLogLine(O_INFO, "foo", 1, "foo status");
  StatusLogLine log2 = makeStatusLogLine(O_ERROR, "bar", 30, "bar error");
  runner.logStatus({log1, log2});
  runner.logString("bar");
  runner.logString("baz");
  EXPECT_CALL(runner, send(ElementsAre("bar", "baz"), "result"))
      .WillOnce(Return(Status(0)));
  EXPECT_CALL(
      runner,
      send(ElementsAre(MatchesStatus(log1), MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(0)));
  runner.check();
  // This call should not result in sending again
  runner.check();
}

TEST_F(BufferedLogForwarderTests, test_retry) {
  StrictMock<MockBufferedLogForwarder> runner;
  runner.logString("foo");

  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  // This call should try to send again because the first failed
  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  StatusLogLine log1 = makeStatusLogLine(O_INFO, "foo", 1, "foo status");
  StatusLogLine log2 = makeStatusLogLine(O_ERROR, "bar", 30, "bar error");
  runner.logStatus({log1});
  runner.logStatus({log2});
  runner.logString("bar");
  EXPECT_CALL(runner, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(0)));
  EXPECT_CALL(
      runner,
      send(ElementsAre(MatchesStatus(log1), MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  EXPECT_CALL(
      runner,
      send(ElementsAre(MatchesStatus(log1), MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(0)));
  runner.check();

  // This call should not send again because the previous was successful
  runner.check();
}

TEST_F(BufferedLogForwarderTests, test_multiple) {
  // Test for the scenario in which multiple logger plugins are using the base
  // class and buffering to the backing store
  StrictMock<MockBufferedLogForwarder> runner1("mock1");
  StrictMock<MockBufferedLogForwarder> runner2("mock2");
  runner1.logString("foo");
  runner2.logString("bar");

  EXPECT_CALL(runner1, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner1.check();
  EXPECT_CALL(runner2, send(ElementsAre("bar"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner2.check();

  // This call should try to send again because the first failed
  EXPECT_CALL(runner1, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner1.check();
  EXPECT_CALL(runner2, send(ElementsAre("bar"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner2.check();

  StatusLogLine log1 = makeStatusLogLine(O_INFO, "foo", 1, "foo status");
  StatusLogLine log2 = makeStatusLogLine(O_ERROR, "bar", 30, "bar error");
  runner1.logStatus({log1});
  runner2.logStatus({log2});
  runner1.logString("bar");
  EXPECT_CALL(runner1, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(0)));
  EXPECT_CALL(runner1, send(ElementsAre(MatchesStatus(log1)), "status"))
      .WillOnce(Return(Status(1, "fail")));
  runner1.check();

  EXPECT_CALL(runner2, send(ElementsAre("bar"), "result"))
      .WillOnce(Return(Status(0)));
  EXPECT_CALL(runner2, send(ElementsAre(MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(1, "fail")));
  runner2.check();

  // Should retry and succeed
  EXPECT_CALL(runner1, send(ElementsAre(MatchesStatus(log1)), "status"))
      .WillOnce(Return(Status(0)));
  runner1.check();
  EXPECT_CALL(runner2, send(ElementsAre(MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(0)));
  runner2.check();

  // This call should not send again because the previous was successful
  runner1.check();
  runner2.check();
}

TEST_F(BufferedLogForwarderTests, test_async) {
  auto runner = std::make_shared<StrictMock<MockBufferedLogForwarder>>(
      "mock", kLogPeriod);

  EXPECT_CALL(*runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0)));
  runner->logString("foo");

  Dispatcher::addService(runner);
  runner->interrupt();
  Dispatcher::joinServices();
}

// Verify that the max number of logs per send is respected
TEST_F(BufferedLogForwarderTests, test_split) {
  StrictMock<MockBufferedLogForwarder> runner("mock", kLogPeriod, 1);
  runner.logString("foo");
  runner.logString("bar");
  runner.logString("baz");

  // Expect that all three calls are sent separately
  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0)));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("bar"), "result"))
      .WillOnce(Return(Status(0)));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("baz"), "result"))
      .WillOnce(Return(Status(0)));
  runner.check();

  StrictMock<MockBufferedLogForwarder> runner2("mock", kLogPeriod, 2);
  runner2.logString("foo");
  runner2.logString("bar");
  runner2.logString("baz");

  // Expect that the first two are sent together
  EXPECT_CALL(runner2, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner2.check();

  EXPECT_CALL(runner2, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(0)));
  runner2.check();

  // Then the last when the first two are successful
  EXPECT_CALL(runner2, send(ElementsAre("baz"), "result"))
      .WillOnce(Return(Status(0)));
  runner2.check();
}

// Test the purge() function independently of check()
TEST_F(BufferedLogForwarderTests, test_purge) {
  FLAGS_buffered_log_max = 3;
  StrictMock<MockBufferedLogForwarder> runner("mock", kLogPeriod, 100);
  uint64_t time = getUnixTime();
  for (uint64_t i = 0; i < 10; ++i) {
    runner.logString(std::to_string(i), time);
    StatusLogLine log1 = makeStatusLogLine(O_INFO, "foo", 1, "foo status");
    StatusLogLine log2 = makeStatusLogLine(O_ERROR, "bar", 30, "bar error");
    runner.logStatus({log1, log2}, time);
    ++time;
  }
  runner.logString("foo", time);
  runner.purge();
  runner.logString("bar", time);
  runner.purge();
  runner.logString("baz", time);
  runner.purge();
  runner.purge();

  EXPECT_CALL(runner, send(ElementsAre("foo", "bar", "baz"), "result"))
      .WillOnce(Return(Status(0)));
  runner.check();

  runner.check();
}

// Verify that the max number of buffered logs is respected, and oldest logs
// are purged first
TEST_F(BufferedLogForwarderTests, test_purge_max) {
  FLAGS_buffered_log_max = 2;

  StrictMock<MockBufferedLogForwarder> runner("mock", kLogPeriod, 5);
  StatusLogLine log1 = makeStatusLogLine(O_INFO, "foo", 1, "foo status");
  StatusLogLine log2 = makeStatusLogLine(O_ERROR, "bar", 30, "bar error");
  uint64_t time = getUnixTime();

  runner.logString("foo", time);
  runner.logStatus({log1}, time);
  ++time;
  runner.logString("bar", time);
  ++time;
  runner.logStatus({log2}, time);
  runner.logString("baz", time);

  EXPECT_CALL(runner, send(ElementsAre("foo", "bar", "baz"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  EXPECT_CALL(
      runner,
      send(ElementsAre(MatchesStatus(log1), MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("baz"), "result"))
      .WillOnce(Return(Status(0)));
  EXPECT_CALL(runner, send(ElementsAre(MatchesStatus(log2)), "status"))
      .WillOnce(Return(Status(0)));
  runner.check();

  ++time;
  runner.logString("1", time);
  runner.logString("2", time);
  runner.logString("3", time);

  EXPECT_CALL(runner, send(ElementsAre("1", "2", "3"), "result"))
      .WillOnce(Return(Status(0)));
  runner.check();

  runner.check();
}
}
