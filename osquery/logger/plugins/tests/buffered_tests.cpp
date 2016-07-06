/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/tests/test_util.h"
#include "osquery/logger/plugins/buffered.h"

using namespace testing;
namespace pt = boost::property_tree;

namespace osquery {

// Check that the string matches the StatusLogLine
MATCHER_P(MatchesStatus, expected, "") {
  pt::ptree actual;
  std::stringstream json_in(arg);
  try {
    pt::read_json(json_in, actual);
    return expected.severity == actual.get<int>("severity") &&
           expected.filename == actual.get<std::string>("filename") &&
           expected.line == actual.get<int>("line") &&
           expected.message == actual.get<std::string>("message");
  } catch (const std::exception& e) {
    return false;
  }
}

class BufferedLogForwarderTests : public Test {
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
  using BufferedLogForwarder::BufferedLogForwarder;
  MockBufferedLogForwarder() : BufferedLogForwarder("mock") {}

  MOCK_METHOD2(send,
               Status(std::vector<std::string>& log_data,
                      const std::string& log_type));
  FRIEND_TEST(BufferedLogForwarderTests, test_index);
  FRIEND_TEST(BufferedLogForwarderTests, test_basic);
  FRIEND_TEST(BufferedLogForwarderTests, test_retry);
  FRIEND_TEST(BufferedLogForwarderTests, test_multiple);
  FRIEND_TEST(BufferedLogForwarderTests, test_async);
  FRIEND_TEST(BufferedLogForwarderTests, test_split);
};

TEST_F(BufferedLogForwarderTests, test_index) {
  MockBufferedLogForwarder runner;
  EXPECT_THAT(runner.genResultIndex(), ContainsRegex("mock_r_[0-9]+_1"));
  EXPECT_THAT(runner.genStatusIndex(), ContainsRegex("mock_s_[0-9]+_2"));
  EXPECT_THAT(runner.genResultIndex(), ContainsRegex("mock_r_[0-9]+_3"));
  EXPECT_THAT(runner.genStatusIndex(), ContainsRegex("mock_s_[0-9]+_4"));

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
  Dispatcher::addService(runner);

  EXPECT_CALL(*runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0)));
  runner->logString("foo");
  std::this_thread::sleep_for(5 * kLogPeriod);

  EXPECT_CALL(*runner, send(ElementsAre("bar"), "result"))
      .Times(3)
      .WillOnce(Return(Status(1, "fail")))
      .WillOnce(Return(Status(1, "fail again")))
      .WillOnce(Return(Status(0)));
  runner->logString("bar");
  std::this_thread::sleep_for(15 * kLogPeriod);

  Dispatcher::stopServices();
  Dispatcher::joinServices();
}

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
}
