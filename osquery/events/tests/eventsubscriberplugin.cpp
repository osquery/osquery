/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "mockedosquerydatabase.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include <gtest/gtest.h>

#include <osquery/events/eventsubscriber.h>
#include <osquery/logger/logger.h>

namespace osquery {

class EventSubscriberPluginTests : public testing::Test {};

namespace {

/// Collects the warnings logged while it is alive
class WarningCapture final : public google::LogSink {
 public:
  WarningCapture() {
    google::AddLogSink(this);
  }

  ~WarningCapture() override {
    google::RemoveLogSink(this);
  }

  void send(google::LogSeverity severity,
            const char* full_filename,
            const char* base_filename,
            int line,
            const struct ::tm* tm_time,
            const char* message,
            size_t message_len) override {
    if (severity == google::GLOG_WARNING) {
      message_list.emplace_back(message, message_len);
    }
  }

  std::vector<std::string> message_list;
};

} // namespace

TEST_F(EventSubscriberPluginTests, generateEventIdentifier) {
  EventSubscriberPlugin::Context context;
  auto event_id1 = EventSubscriberPlugin::generateEventIdentifier(context);
  auto event_id2 = EventSubscriberPlugin::generateEventIdentifier(context);
  ASSERT_TRUE(event_id1 + 1 == event_id2);
}

TEST_F(EventSubscriberPluginTests, setDatabaseNamespace) {
  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");
  ASSERT_EQ(context.database_namespace, "type.name");
}

TEST_F(EventSubscriberPluginTests, generateEventDataIndex) {
  // We start with 10 good keys and 10 malformed ones
  MockedOsqueryDatabase mocked_database;
  mocked_database.generateEvents("type", "name");
  EXPECT_EQ(mocked_database.key_map.size(), 20U);

  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");

  // The reindex will erase the malformed keys and leave us with
  // just the 10 good ones
  auto status =
      EventSubscriberPlugin::generateEventDataIndex(context, mocked_database);

  // Make sure we have found the 10 keys and that the broken ones
  // have been deleted
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(mocked_database.key_map.size(), 10U);
  EXPECT_EQ(context.event_index.size(), 10U);
}

TEST_F(EventSubscriberPluginTests, toIndex) {
  auto index = EventSubscriberPlugin::toIndex(1);
  EXPECT_EQ(index, "0000000001");
}

TEST_F(EventSubscriberPluginTests, setOptimizeData) {
  MockedOsqueryDatabase mocked_database;
  mocked_database.generateEvents("type", "name");
  EXPECT_EQ(mocked_database.key_map.size(), 20U);

  const EventTime kEventTime{10U};
  const std::size_t kEventIdentifier{20U};
  EventSubscriberPlugin::setOptimizeData(
      mocked_database, kEventTime, kEventIdentifier);

  EXPECT_EQ(mocked_database.key_map.size(), 22U);

  ASSERT_EQ(mocked_database.key_map.count("optimize.test_query"), 1U);
  EXPECT_EQ(mocked_database.key_map.at("optimize.test_query"),
            std::to_string(kEventTime));

  std::stringstream expected_eid;
  expected_eid << std::setfill('0') << std::setw(10) << kEventIdentifier;

  ASSERT_EQ(mocked_database.key_map.count("optimize_eid.test_query"), 1U);
  EXPECT_EQ(mocked_database.key_map.at("optimize_eid.test_query"),
            expected_eid.str());
}

TEST_F(EventSubscriberPluginTests, timeFromRecord) {
  EventTime kExpectedEventTime{12345U};
  auto event_time =
      EventSubscriberPlugin::timeFromRecord(std::to_string(kExpectedEventTime));

  EXPECT_EQ(event_time, kExpectedEventTime);
}

TEST_F(EventSubscriberPluginTests, getOptimizeData) {
  MockedOsqueryDatabase mocked_database;
  mocked_database.generateEvents("type", "name");
  EXPECT_EQ(mocked_database.key_map.size(), 20U);

  const EventTime kEventTime{10U};
  const std::size_t kEventIdentifier{20U};
  EventSubscriberPlugin::setOptimizeData(
      mocked_database, kEventTime, kEventIdentifier);

  EventTime event_time{};
  EventID event_id{};
  std::string query_name;
  EventSubscriberPlugin::getOptimizeData(
      mocked_database, event_time, event_id, query_name);

  EXPECT_EQ(kEventTime, event_time);
  EXPECT_EQ(kEventIdentifier, event_id);
  EXPECT_EQ(query_name, "test_query");
}

TEST_F(EventSubscriberPluginTests, databaseKeyForEventId) {
  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");

  const std::size_t kEventIdentifier{1000};

  std::stringstream expected_key;
  expected_key << "data." << context.database_namespace << "."
               << std::setfill('0') << std::setw(10) << kEventIdentifier;

  auto key =
      EventSubscriberPlugin::databaseKeyForEventId(context, kEventIdentifier);

  EXPECT_EQ(key, expected_key.str());
}

TEST_F(EventSubscriberPluginTests, removeOverflowingEventBatches) {
  MockedOsqueryDatabase mocked_database;
  mocked_database.generateEvents("type", "name");
  EXPECT_EQ(mocked_database.key_map.size(), 20U);

  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");

  auto status =
      EventSubscriberPlugin::generateEventDataIndex(context, mocked_database);

  ASSERT_TRUE(status.ok());
  EXPECT_EQ(context.event_index.size(), 10U);

  // Try with a limit of 20 batches; this shouldn't change how many
  // items we have in the index
  EventSubscriberPlugin::removeOverflowingEventBatches(
      context, mocked_database, 20U);

  EXPECT_EQ(context.event_index.size(), 10U);

  // Try with a limit of 6 batches; this should remove 4
  EventSubscriberPlugin::removeOverflowingEventBatches(
      context, mocked_database, 6U);

  EXPECT_EQ(context.event_index.size(), 6U);

  // Try again with a limit of 4; this should remove an additional 2
  EventSubscriberPlugin::removeOverflowingEventBatches(
      context, mocked_database, 4U);

  EXPECT_EQ(context.event_index.size(), 4U);

  // Going higher than 4 will have no effect
  EventSubscriberPlugin::removeOverflowingEventBatches(
      context, mocked_database, 5U);

  EXPECT_EQ(context.event_index.size(), 4U);
}

TEST_F(EventSubscriberPluginTests, removeOverflowingEventBatchesLog) {
  MockedOsqueryDatabase mocked_database;
  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");

  // Batches with more than one event; the warning counts batches, see
  // https://github.com/osquery/osquery/issues/8570
  context.event_index = {{1, {1, 2, 3}},
                         {2, {4, 5}},
                         {3, {6, 7, 8}},
                         {4, {9, 10, 11}},
                         {5, {12, 13}},
                         {6, {14, 15}},
                         {7, {16}}};
  for (EventID id = 1; id <= 16; ++id) {
    mocked_database.key_map.insert(
        {EventSubscriberPlugin::databaseKeyForEventId(context, id), "{}"});
  }

  auto remove_batches = [&](std::size_t max_event_batches) {
    WarningCapture capture;
    EventSubscriberPlugin::removeOverflowingEventBatches(
        context, mocked_database, max_event_batches);
    return capture.message_list;
  };

  // Batches 1 and 2
  std::vector<std::string> expected = {
      "Removed 2 event batches for subscriber: type.name (limit: 5, last "
      "query: never)"};
  EXPECT_EQ(remove_batches(5U), expected);
  EXPECT_EQ(mocked_database.key_map.size(), 11U);

  // A batch is only removed if all of its events are: one event of batch 3
  // and all of batch 4 fail, batch 5 succeeds
  for (EventID id : {7, 9, 10, 11, 14, 15}) {
    mocked_database.failed_delete_key_set.insert(
        EventSubscriberPlugin::databaseKeyForEventId(context, id));
  }

  expected = {
      "Removed 1 of 3 event batches (4 events failed to delete) for "
      "subscriber: type.name (limit: 2, last query: never)"};
  EXPECT_EQ(remove_batches(2U), expected);
  EXPECT_EQ(mocked_database.key_map.size(), 7U);

  // Batch 6, none of its events can be deleted
  expected = {
      "Removed 0 of 1 event batches (2 events failed to delete) for "
      "subscriber: type.name (limit: 1, last query: never)"};
  EXPECT_EQ(remove_batches(1U), expected);
  EXPECT_EQ(mocked_database.key_map.size(), 7U);
  EXPECT_EQ(context.event_index.size(), 1U);
}

TEST_F(EventSubscriberPluginTests, expireEventBatches) {
  MockedOsqueryDatabase mocked_database;
  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");

  auto status =
      EventSubscriberPlugin::generateEventDataIndex(context, mocked_database);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(context.event_index.size(), 0U);
  EventIndex index;
  EXPECT_EQ(context.event_index, index);

  mocked_database.generateEvents("type", "name");
  EXPECT_EQ(mocked_database.key_map.size(), 20U);

  status =
      EventSubscriberPlugin::generateEventDataIndex(context, mocked_database);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(context.event_index.size(), 10U);

  EventSubscriberPlugin::expireEventBatches(context, mocked_database, 0, 0);
  EXPECT_EQ(context.event_index.size(), 10U);

  EventSubscriberPlugin::expireEventBatches(context, mocked_database, 1, 0);
  EXPECT_EQ(context.event_index.size(), 10U);

  EventSubscriberPlugin::expireEventBatches(context, mocked_database, 1, 5);
  EXPECT_EQ(context.event_index.size(), 5U);

  // One event should be left (see
  // https://github.com/osquery/osquery/issues/8524)
  EventSubscriberPlugin::expireEventBatches(context, mocked_database, 1, 15);
  EXPECT_EQ(context.event_index.size(), 1U);
}

TEST_F(EventSubscriberPluginTests, generateRows) {
  MockedOsqueryDatabase mocked_database;
  mocked_database.generateEvents("type", "name");
  EXPECT_EQ(mocked_database.key_map.size(), 20U);

  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, "type", "name");

  auto status =
      EventSubscriberPlugin::generateEventDataIndex(context, mocked_database);

  ASSERT_TRUE(status.ok());
  EXPECT_EQ(context.event_index.size(), 10U);

  std::size_t callback_count{0U};
  auto callback = [&callback_count](Row) { ++callback_count; };

  auto result = EventSubscriberPlugin::generateRows(
      context, mocked_database, callback, 2, 1);
  EXPECT_EQ(callback_count, 0U);
  EXPECT_EQ(result.isEnd, true);

  result = EventSubscriberPlugin::generateRows(
      context, mocked_database, callback, 0, 0);
  EXPECT_EQ(callback_count, 10U);
  EXPECT_EQ(result.isEnd, false);
  EXPECT_EQ(result.last_time, 9U);

  result = EventSubscriberPlugin::generateRows(
      context, mocked_database, callback, 0, 4);
  EXPECT_EQ(callback_count, 15U);
  EXPECT_EQ(result.isEnd, false);
  EXPECT_EQ(result.last_time, 4U);

  result = EventSubscriberPlugin::generateRows(
      context, mocked_database, callback, 5, 9);
  EXPECT_EQ(callback_count, 20U);
  EXPECT_EQ(result.isEnd, false);
  EXPECT_EQ(result.last_time, 9U);

  result = EventSubscriberPlugin::generateRows(
      context, mocked_database, callback, 10, 15);
  EXPECT_EQ(callback_count, 20U);
  EXPECT_EQ(result.isEnd, true);
}

class FakeEventSubscriberPlugin : public EventSubscriberPlugin {
 public:
  FakeEventSubscriberPlugin(IDatabaseInterface& db)
      : EventSubscriberPlugin(true), db_{db} {
    setName("fake");
  };

  const std::string& getType() const override {
    static std::string name{"fake"};
    return name;
  }

  void setShouldOptimize(bool optimize) {
    optimize_ = optimize;
  }

  uint64_t getTime() const override {
    return time_;
  }

  void setTime(uint64_t t) {
    time_ = t;
  }

  void setEventsExpiry(size_t expiry) {
    expiry_ = expiry;
  }

  size_t getEventsExpiry() override {
    return expiry_;
  }

 private:
  bool shouldOptimize() const override {
    return optimize_;
  }

  IDatabaseInterface& getDatabase() const override {
    return db_;
  }

 private:
  bool optimize_{false};
  IDatabaseInterface& db_;
  uint64_t time_{0};
  size_t expiry_{0};
};

TEST_F(EventSubscriberPluginTests, getExpireTime) {
  MockedOsqueryDatabase mocked_database;
  FakeEventSubscriberPlugin subscriber(mocked_database);

  subscriber.setTime(10);
  auto expire_time = subscriber.getExpireTime();
  ASSERT_EQ(10U, subscriber.getTime());
  EXPECT_EQ(subscriber.getTime(), expire_time);

  subscriber.resetQueryCount(2);
  // A count without any executed queries returns the current time.
  expire_time = subscriber.getExpireTime();
  EXPECT_EQ(subscriber.getTime(), expire_time);

  // The expire time is the least recent executed query time.
  subscriber.setExecutedQuery("test1", 2);
  subscriber.setExecutedQuery("test2", 5);
  expire_time = subscriber.getExpireTime();
  EXPECT_EQ(2U, expire_time);

  subscriber.setExecutedQuery("test1", 10);
  expire_time = subscriber.getExpireTime();
  EXPECT_EQ(5U, expire_time);
}

TEST_F(EventSubscriberPluginTests, getEventsExpiry) {
  MockedOsqueryDatabase mocked_database;
  FakeEventSubscriberPlugin subscriber(mocked_database);

  subscriber.setEventsExpiry(10);
  auto expiry = subscriber.getMinExpiry();
  EXPECT_EQ(10U, expiry);

  subscriber.setMinExpiry(20);
  expiry = subscriber.getMinExpiry();
  EXPECT_EQ(20U, expiry);

  subscriber.setMinExpiry(5);
  expiry = subscriber.getMinExpiry();
  EXPECT_EQ(10U, expiry);
}

TEST_F(EventSubscriberPluginTests, generateRowsWithExpiry) {
  MockedOsqueryDatabase mocked_database;
  FakeEventSubscriberPlugin subscriber(mocked_database);
  mocked_database.generateEvents(subscriber.getType(), subscriber.getName());

  subscriber.setDatabaseNamespace();
  subscriber.generateEventDataIndex();
  subscriber.setEventsExpiry(100);

  // Always return true for "executedAllQueries".
  subscriber.resetQueryCount(0);
  subscriber.setShouldOptimize(false);
  ASSERT_TRUE(subscriber.executedAllQueries());

  size_t callback_count{0U};
  auto callback = [&callback_count](Row) { ++callback_count; };
  // Time is in the future.
  subscriber.setTime(20);
  subscriber.generateRows(callback, true, 0, 0);
  EXPECT_EQ(10U, callback_count);

  // Events are expired after being queried (except for last valid event --
  // optimize should take care of that event not being returned again, but that
  // is tested separately below.)
  callback_count = 0;
  subscriber.generateRows(callback, true, 0, 0);
  EXPECT_EQ(1U, callback_count);
}

TEST_F(EventSubscriberPluginTests, generateRowsWithOptimize) {
  MockedOsqueryDatabase mocked_database;
  FakeEventSubscriberPlugin subscriber(mocked_database);
  mocked_database.generateEvents(subscriber.getType(), subscriber.getName());

  subscriber.setDatabaseNamespace();
  subscriber.generateEventDataIndex();

  subscriber.resetQueryCount(2);
  subscriber.setShouldOptimize(false);

  size_t callback_count{0U};
  auto callback = [&callback_count](Row) { ++callback_count; };
  subscriber.generateRows(callback, true, 0, 0);
  // Queries are not tracked when not optimizing.
  EXPECT_EQ(0U, subscriber.queries_.size());
  EXPECT_EQ(10U, callback_count);

  const EventTime event_time{0U};
  const EventID event_id{0U};
  subscriber.setOptimizeData(mocked_database, event_time, event_id);

  callback_count = 0;
  subscriber.setShouldOptimize(true);
  subscriber.generateRows(callback, true, 0, 5);
  EXPECT_EQ(6U, callback_count);
  EXPECT_EQ(1U, subscriber.queries_.size());

  // This should continue from the optimized placement.
  callback_count = 0;
  subscriber.generateRows(callback, true, 0, 0);
  EXPECT_EQ(4U, callback_count);
  EXPECT_EQ(1U, subscriber.queries_.size());

  callback_count = 0;
  subscriber.generateRows(callback, true, 0, 0);
  ASSERT_FALSE(subscriber.executedAllQueries());
  EXPECT_EQ(0U, callback_count);
}
} // namespace osquery
