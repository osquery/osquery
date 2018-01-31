/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
    if (publishedMsgs_.find(topic) == publishedMsgs_.end()) {
      std::vector<std::string> msgs;
      publishedMsgs_[topic] = msgs;
    }

    publishedMsgs_[topic].push_back(payload);

    return Status(0, "OK");
  }

  void flushMessages() override {
    timesFlushed_++;
  }

  void pollKafka() override {
    timesPolled_++;
  }

 public:
  std::map<rd_kafka_topic_t*, std::vector<std::string>> publishedMsgs_;

  std::atomic<int> timesFlushed_;

  std::atomic<int> timesPolled_;
};

class KafkaProducerPluginTest : public ::testing::Test {};

TEST_F(KafkaProducerPluginTest, getMsgName_tests) {
  // Key is `input`, Value is `expected`
  std::map<std::string, std::string> tests = {
      {"{\"name\": \"foo\"}", "foo"},
      {"{\"snapshot\":[{\"active_disks\":\"6\",\"bitmap_chunk_size\":\"\","
       "\"bitmap_external_file\":\"\",\"bitmap_on_mem\":\"\",\"check_array_"
       "finish\":\"\",\"check_array_progress\":\"\",\"check_array_speed\":\"\","
       "\"chunk_size\":\"0\",\"device_name\":\"md0\",\"failed_disks\":\"0\","
       "\"nr_raid_disks\":\"6\",\"other\":\"super "
       "1.2\",\"raid_disks\":\"6\",\"raid_level\":\"1\",\"recovery_finish\":"
       "\"\",\"recovery_progress\":\"\",\"recovery_speed\":\"\",\"reshape_"
       "finish\":\"\",\"reshape_progress\":\"\",\"reshape_speed\":\"\","
       "\"resync_finish\":\"\",\"resync_progress\":\"\",\"resync_speed\":\"\","
       "\"size\":\"248640\",\"spare_disks\":\"0\",\"status\":\"active\","
       "\"superblock_state\":\"clean\",\"superblock_update_time\":"
       "\"1501097120\",\"superblock_version\":\"1.2\",\"unused_devices\":\"<"
       "none>\",\"working_disks\":\"6\"},{\"active_disks\":\"6\",\"bitmap_"
       "chunk_size\":\"\",\"bitmap_external_file\":\"\",\"bitmap_on_mem\":\"\","
       "\"check_array_finish\":\"\",\"check_array_progress\":\"\",\"check_"
       "array_speed\":\"\",\"chunk_size\":\"524288\",\"device_name\":\"md1\","
       "\"failed_disks\":\"0\",\"nr_raid_disks\":\"6\",\"other\":\"super 1.2 "
       "512K chunks 2 "
       "near-copies\",\"raid_disks\":\"6\",\"raid_level\":\"10\",\"recovery_"
       "finish\":\"\",\"recovery_progress\":\"\",\"recovery_speed\":\"\","
       "\"reshape_finish\":\"\",\"reshape_progress\":\"\",\"reshape_speed\":"
       "\"\",\"resync_finish\":\"\",\"resync_progress\":\"\",\"resync_speed\":"
       "\"\",\"size\":\"4687296000\",\"spare_disks\":\"0\",\"status\":"
       "\"active\",\"superblock_state\":\"unknown\",\"superblock_update_time\":"
       "\"1501097303\",\"superblock_version\":\"1.2\",\"unused_devices\":\"<"
       "none>\",\"working_disks\":\"6\"}],\"action\":\"snapshot\",\"name\":"
       "\"bar\",\"hostIdentifier\":\"node151\",\"calendarTime\":\"Wed Jul "
       "26 19:29:22 2017 UTC\",\"unixTime\":\"1501097362\",\"epoch\":\"0\"}",
       "bar"},
      {"{\"snapshot\":[{\"active_disks\":\"6\",\"bitmap_chunk_size\":\"\","
       "\"bitmap_external_file\":\"\",\"bitmap_on_mem\":\"\",\"check_array_"
       "finish\":\"\",\"check_array_progress\":\"\",\"check_array_speed\":\"\","
       "\"chunk_size\":\"0\",\"device_name\":\"md0\",\"failed_disks\":\"0\","
       "\"nr_raid_disks\":\"6\",\"other\":\"super "
       "1.2\",\"raid_disks\":\"6\",\"raid_level\":\"1\",\"recovery_finish\":"
       "\"\",\"recovery_progress\":\"\",\"recovery_speed\":\"\",\"reshape_"
       "finish\":\"\",\"reshape_progress\":\"\",\"reshape_speed\":\"\","
       "\"resync_finish\":\"\",\"resync_progress\":\"\",\"resync_speed\":\"\","
       "\"size\":\"248640\",\"spare_disks\":\"0\",\"status\":\"active\","
       "\"superblock_state\":\"clean\",\"superblock_update_time\":"
       "\"1501097120\",\"superblock_version\":\"1.2\",\"unused_devices\":\"<"
       "none>\",\"working_disks\":\"6\"},{\"active_disks\":\"6\",\"bitmap_"
       "chunk_size\":\"\",\"bitmap_external_file\":\"\",\"bitmap_on_mem\":\"\","
       "\"check_array_finish\":\"\",\"check_array_progress\":\"\",\"check_"
       "array_speed\":\"\",\"chunk_size\":\"524288\",\"device_name\":\"md1\","
       "\"failed_disks\":\"0\",\"nr_raid_disks\":\"6\",\"other\":\"super 1.2 "
       "512K chunks 2 "
       "near-copies\",\"raid_disks\":\"6\",\"raid_level\":\"10\",\"recovery_"
       "finish\":\"\",\"recovery_progress\":\"\",\"recovery_speed\":\"\","
       "\"reshape_finish\":\"\",\"reshape_progress\":\"\",\"reshape_speed\":"
       "\"\",\"resync_finish\":\"\",\"resync_progress\":\"\",\"resync_speed\":"
       "\"\",\"size\":\"4687296000\",\"spare_disks\":\"0\",\"status\":"
       "\"active\",\"superblock_state\":\"unknown\",\"superblock_update_time\":"
       "\"1501097303\",\"superblock_version\":\"1.2\",\"unused_devices\":\"<"
       "none>\",\"working_disks\":\"6\"}],\"action\":\"snapshot\","
       "\"hostIdentifier\":\"node151\",\"calendarTime\":\"Wed Jul "
       "26 19:29:22 2017 UTC\",\"unixTime\":\"1501097362\",\"epoch\":\"0\"}",
       ""},
  };

  for (const auto& test : tests) {
    EXPECT_EQ(getMsgName(test.first), test.second);
  }
}

TEST_F(KafkaProducerPluginTest, logString_single_topic_happy_path) {
  MockKafkaProducerPlugin mkpp;

  std::map<std::string, rd_kafka_topic_t*> qToT;

  /* Set some fake address so won't evaluate true for nullptr check.  Use
   * reinterpret_cast since rd_kafka_topic_t is opaque. */
  rd_kafka_topic_t* topic = reinterpret_cast<rd_kafka_topic_t*>(0x692870);
  qToT[kKafkaBaseTopic] = topic;
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

  EXPECT_EQ(msgs, mkpp.publishedMsgs_[topic]);

  EXPECT_TRUE(mkpp.timesPolled_.load() == 4);
}

TEST_F(KafkaProducerPluginTest, logString_multi_topic_happy_path) {
  MockKafkaProducerPlugin mkpp;

  std::map<std::string, rd_kafka_topic_t*> qToT;

  /* Set some fake address so won't evaluate true for nullptr check.  Use
   * reinterpret_cast since rd_kafka_topic_t is opaque. */
  rd_kafka_topic_t* topicBase = reinterpret_cast<rd_kafka_topic_t*>(0x692870);
  qToT[kKafkaBaseTopic] = topicBase;

  rd_kafka_topic_t* topic1 = reinterpret_cast<rd_kafka_topic_t*>(0x692871);
  qToT["topic1"] = topic1;

  rd_kafka_topic_t* topic2 = reinterpret_cast<rd_kafka_topic_t*>(0x692872);
  qToT["topic2"] = topic2;

  rd_kafka_topic_t* topic3 = reinterpret_cast<rd_kafka_topic_t*>(0x692873);
  qToT["topic3"] = topic3;

  mkpp.setQueryToTopics(qToT);

  std::vector<std::string> msgs = {
      "{\"name\": \"topic1\", \"snapshot\": \"1\"}",
      "{\"name\": \"topic10\", \"snapshot\": \"2\"}",
      "{\"name\": \"topic2\", \"snapshot\": \"3\"}",
      "{\"name\": \"topic3\", \"snapshot\": \"4\"}",
      "{\"name\": \"topic13\", \"snapshot\": \"5\"}",
      "{\"name\": \"topic1\", \"snapshot\": \"6\"}",
      "{\"name\": \"topic3\", \"snapshot\": \"7\"}",
      "{\"name\": \"topic3\", \"snapshot\": \"8\"}",
  };

  for (auto& m : msgs) {
    Status s = mkpp.logString(m);
    EXPECT_TRUE(s.ok());
  }

  std::vector<std::string> expected;
  expected = {
      "{\"name\": \"topic10\", \"snapshot\": \"2\"}",
      "{\"name\": \"topic13\", \"snapshot\": \"5\"}",
  };
  EXPECT_EQ(expected, mkpp.publishedMsgs_[topicBase]);

  expected = {
      "{\"name\": \"topic1\", \"snapshot\": \"1\"}",
      "{\"name\": \"topic1\", \"snapshot\": \"6\"}",
  };
  EXPECT_EQ(expected, mkpp.publishedMsgs_[topic1]);

  expected = {
      "{\"name\": \"topic2\", \"snapshot\": \"3\"}",
  };
  EXPECT_EQ(expected, mkpp.publishedMsgs_[topic2]);

  expected = {
      "{\"name\": \"topic3\", \"snapshot\": \"4\"}",
      "{\"name\": \"topic3\", \"snapshot\": \"7\"}",
      "{\"name\": \"topic3\", \"snapshot\": \"8\"}",
  };
  EXPECT_EQ(expected, mkpp.publishedMsgs_[topic3]);

  EXPECT_TRUE(mkpp.timesPolled_.load() == 8);
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
