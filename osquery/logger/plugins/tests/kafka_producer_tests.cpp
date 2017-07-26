/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <iostream>

#include "boost/date_time/posix_time/posix_time.hpp"
#include <boost/asio.hpp>
#include <boost/chrono.hpp>

#include <osquery/core.h>
#include <osquery/status.h>

#include "osquery/logger/plugins/kafka_producer.h"

namespace osquery {

class MockKafkaProducerPlugin : public KafkaProducerPlugin {
 public:
  MockKafkaProducerPlugin() : timesFlushed_(0), timesPolled_(0) {
    running_ = true;
  }

  bool isRunning() {
    return running_.load();
  }

  void setQueryToTopics(const std::map<std::string, rd_kafka_topic_t*>& m) {
    queryToTopics_ = m;
  }

 protected:
  Status publishMsg(rd_kafka_topic_t* topic,
                    const std::string& payload) override {
    publishedMsgs_.push_back(payload);

    return Status(0, "OK");
  }

  void flushMessages() override {
    timesFlushed_++;
  }

  void pollKafka() override {
    timesPolled_++;
  }

 public:
  std::vector<std::string> publishedMsgs_;

  std::atomic<int> timesFlushed_;

  std::atomic<int> timesPolled_;
};

class KafkaProducerPluginTest : public ::testing::Test {};

TEST_F(KafkaProducerPluginTest, logString_happy_path) {
  MockKafkaProducerPlugin mkpp;

  std::map<std::string, rd_kafka_topic_t*> qToT;

  /* Set some fake address so won't evaluate true for nullptr check.  Use
   * reinterpret_cast since rd_kafka_topic_t is opaque. */
  qToT[kKafkaBaseTopic] = reinterpret_cast<rd_kafka_topic_t*>(0x692870);
  mkpp.setQueryToTopics(qToT);

  std::vector<std::string> msgs = {
      "{\"name\": \"test1\"}",
      "{\"name\": \"test2\"}",
      "{\"name\": \"test3\"}",
      "{\"name\": \"test4\"}",
  };

  for (auto& m : msgs) {
    Status s = mkpp.logString(m);
    EXPECT_TRUE(s.ok());
  }

  EXPECT_EQ(msgs, mkpp.publishedMsgs_);

  EXPECT_TRUE(mkpp.timesPolled_.load() == 4);
}

TEST_F(KafkaProducerPluginTest, flush_on_stop) {
  MockKafkaProducerPlugin mkpp;

  auto _ = std::async(std::launch::async, [&mkpp]() { mkpp.start(); });

  // Timout for a bit to ensure bg loop starts.
  boost::asio::io_service io_service;
  boost::asio::deadline_timer timer(io_service);
  timer.expires_from_now(boost::posix_time::milliseconds(200));
  timer.wait();

  mkpp.stop();

  EXPECT_TRUE(mkpp.timesFlushed_.load() == 1);
  EXPECT_FALSE(mkpp.isRunning());
}

} // namespace osquery
