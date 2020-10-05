/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gflags/gflags.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <iostream>
#include <thread>

#include "boost/date_time/posix_time/posix_time.hpp"
#include <boost/chrono.hpp>

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/utils/status/status.h>

#include "plugins/logger/kafka_producer.h"

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

class KafkaProducerPluginTest : public ::testing::Test {
 protected:
  void SetUp() {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

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
      // batch mode result without "name" column(s)
      {"{\"diffResults\":{\"removed\":[{\"cmdline\":\"\",\"on_disk\":\"-1\","
       "\"path\":\"\""
       ",\"pid\":\"4453\",\"state\":\"I\",\"uid\":\"0\"},{\"cmdline\":\"\","
       "\"on_disk\":"
       "\"-1\",\"path\":\"\",\"pid\":\"7230\",\"state\":\"I\",\"uid\":\"0\"},{"
       "\"cmdline\""
       ":\"\",\"on_disk\":\"-1\",\"path\":\"\",\"pid\":\"8497\",\"state\":"
       "\"I\",\"uid\""
       ":\"0\"},{\"cmdline\":\"osqueryd --verbose --flagfile "
       "/etc/osquery/osquery.kafka."
       "flags\",\"on_disk\":\"1\",\"path\":\"/usr/local/bin/"
       "osqueryd\",\"pid\":\"8483\","
       "\"state\":\"S\",\"uid\":\"0\"},{\"cmdline\":\"sudo osqueryd --verbose "
       "--flagfil"
       "e "
       "/etc/osquery/osquery.kafka.flags\",\"on_disk\":\"1\",\"path\":\"/usr/"
       "bin/sudo\""
       ",\"pid\":\"8482\",\"state\":\"S\",\"uid\":\"0\"}],\"added\":[{"
       "\"cmdline\":\"\""
       ",\"on_disk\":\"-1\",\"path\":\"\",\"pid\":\"12423\",\"state\":\"I\","
       "\"uid\":\"0\""
       "},{\"cmdline\":\"\",\"on_disk\":\"-1\",\"path\":\"\",\"pid\":\"13382\","
       "\"state\""
       ":\"I\",\"uid\":\"0\"},{\"cmdline\":\"\",\"on_disk\":\"-1\",\"path\":"
       "\"\",\"pid\""
       ":\"15196\",\"state\":\"I\",\"uid\":\"0\"},{\"cmdline\":\"sudo osqueryd "
       "--verbos"
       "e --flagfile "
       "/etc/osquery/osquery.filesystem.flags\",\"on_disk\":\"1\",\"path\":"
       "\"/usr/bin/"
       "sudo\",\"pid\":\"15821\",\"state\":\"S\",\"uid\":\"0\"},{\"cmdline\""
       ":\"osqueryd --verbose --flagfile "
       "/etc/osquery/osquery.filesystem.flags\",\"on_di"
       "sk\":\"1\",\"path\":\"/usr/local/bin/"
       "osqueryd\",\"pid\":\"15822\",\"state\":\"S"
       "\",\"uid\":\"0\"}]},\"name\":\"pack_sample_running_processes\","
       "\"hostIdentifier\""
       ":\"ip-172-22-1-112\",\"calendarTime\":\"Sat May 16 03:33:36 2020 "
       "UTC\",\"unixTi"
       "me\":1589600016,\"epoch\":0,\"counter\":1,\"numerics\":false}",
       "pack_sample_running_processes"},
      // batch mode result with "name" column(s)
      {"{\"diffResults\":{\"removed\":[{\"cmdline\":\"\",\"on_disk\":\"-1\","
       "\"path\":\"\""
       ",\"pid\":\"4453\",\"name\":\"\",\"state\":\"I\",\"uid\":\"0\"},{"
       "\"cmdline\":\"\""
       ",\"on_disk\":\"-1\",\"path\":\"\",\"pid\":\"7230\",\"name\":\"\","
       "\"state\":\"I\""
       ",\"uid\":\"0\"},{\"cmdline\":\"\",\"on_disk\":\"-1\",\"path\":\"\","
       "\"pid\":\"84"
       "97\",\"name\":\"\",\"state\":\"I\",\"uid\":\"0\"},{\"cmdline\":"
       "\"osqueryd --verb"
       "ose --flagfile "
       "/etc/osquery/osquery.kafka.flags\",\"on_disk\":\"1\",\"path\":\"/"
       "usr/local/bin/"
       "osqueryd\",\"pid\":\"8483\",\"name\":\"osqueryd\",\"state\":\"S\","
       "\"uid\":\"0\"},{\"cmdline\":\"sudo osqueryd --verbose --flagfile "
       "/etc/osquery/os"
       "query.kafka.flags\",\"on_disk\":\"1\",\"path\":\"/usr/bin/"
       "sudo\",\"pid\":\"8482\""
       ",\"name\":\"osqueryd\",\"state\":\"S\",\"uid\":\"0\"}],\"added\":[{"
       "\"cmdline\":"
       "\"\",\"on_disk\":\"-1\",\"path\":\"\",\"pid\":\"12423\",\"name\":\"\","
       "\"state\":"
       "\"I\",\"uid\":\"0\"},{\"cmdline\":\"\",\"on_disk\":\"-1\",\"path\":"
       "\"\",\"pid\":"
       "\"13382\",\"name\":\"\",\"state\":\"I\",\"uid\":\"0\"},{\"cmdline\":"
       "\"\",\"on_di"
       "sk\":\"-1\",\"path\":\"\",\"pid\":\"15196\",\"name\":\"\",\"state\":"
       "\"I\",\"uid\""
       ":\"0\"},{\"cmdline\":\"sudo osqueryd --verbose --flagfile "
       "/etc/osquery/osquery."
       "filesystem.flags\",\"on_disk\":\"1\",\"path\":\"/usr/bin/"
       "sudo\",\"pid\":\"15821\""
       ",\"name\":\"osqueryd\",\"state\":\"S\",\"uid\":\"0\"},{\"cmdline\":"
       "\"osqueryd -"
       "-verbose --flagfile "
       "/etc/osquery/osquery.filesystem.flags\",\"on_disk\":\"1\",\""
       "path\":\"/usr/local/bin/"
       "osqueryd\",\"pid\":\"15822\",\"name\":\"osqueryd\",\"sta"
       "te\":\"S\",\"uid\":\"0\"}]},\"name\":\"pack_sample_running_processes\","
       "\"hostIde"
       "ntifier\":\"ip-172-22-1-112\",\"calendarTime\":\"Sat May 16 03:33:36 "
       "2020 UTC\","
       "\"unixTime\":1589600016,\"epoch\":0,\"counter\":1,\"numerics\":false}",
       "pack_sample_running_processes"},
      // event mode result without "name" column
      {"{\"name\":\"pack_sample_running_processes\",\"hostIdentifier\":\"ip-"
       "172-22-1-112"
       "\",\"calendarTime\":\"Sat May 16 03:35:36 2020 "
       "UTC\",\"unixTime\":1589600136,\"e"
       "poch\":0,\"counter\":2,\"numerics\":false,\"columns\":{\"cmdline\":"
       "\"osqueryd --"
       "verbose --flagfile "
       "/etc/osquery/osquery.filesystem.flags\",\"on_disk\":\"1\",\"p"
       "ath\":\"/usr/local/bin/"
       "osqueryd\",\"pid\":\"15822\",\"state\":\"S\",\"uid\":\"0\""
       "},\"action\":\"removed\"}",
       "pack_sample_running_processes"},
      // event mode result with "name" column
      {"{\"name\":\"pack_sample_running_processes\",\"hostIdentifier\":\"ip-"
       "172-22-1-112"
       "\",\"calendarTime\":\"Sat May 16 03:35:36 2020 "
       "UTC\",\"unixTime\":1589600136,\"e"
       "poch\":0,\"counter\":2,\"numerics\":false,\"columns\":{\"cmdline\":"
       "\"osqueryd --"
       "verbose --flagfile "
       "/etc/osquery/osquery.filesystem.flags\",\"on_disk\":\"1\",\"p"
       "ath\":\"/usr/local/bin/"
       "osqueryd\",\"pid\":\"16351\",\"name\":\"osqueryd\",\"stat"
       "e\":\"S\",\"uid\":\"0\"},\"action\":\"added\"}",
       "pack_sample_running_processes"}};

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

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  mkpp.stop();

  EXPECT_TRUE(mkpp.timesFlushed_.load() == 1);
  EXPECT_FALSE(mkpp.isRunning());
}
} // namespace osquery
