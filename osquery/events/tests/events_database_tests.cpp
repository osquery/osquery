/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/tables.h>

#include "osquery/database/db_handle.h"

namespace osquery {

DECLARE_uint64(events_expiry);

class EventsDatabaseTests : public ::testing::Test {};

class DBFakeEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {
  DECLARE_PUBLISHER("DBFakePublisher");
};

class DBFakeEventSubscriber : public EventSubscriber<DBFakeEventPublisher> {
 public:
  DBFakeEventSubscriber() { setName("DBFakeSubscriber"); }
  /// Add a fake event at time t
  Status testAdd(int t) {
    Row r;
    r["testing"] = "hello from space";
    return add(r, t);
  }
};

TEST_F(EventsDatabaseTests, test_event_module_id) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  sub->doNotExpire();

  // Not normally available outside of EventSubscriber->Add().
  auto event_id1 = sub->getEventID();
  EXPECT_EQ(event_id1, "1");
  auto event_id2 = sub->getEventID();
  EXPECT_EQ(event_id2, "2");
}

TEST_F(EventsDatabaseTests, test_event_add) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(1);
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsDatabaseTests, test_record_indexing) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(2);
  status = sub->testAdd(11);
  status = sub->testAdd(61);
  status = sub->testAdd((1 * 3600) + 1);
  status = sub->testAdd((2 * 3600) + 1);

  // An "all" range, will pick up everything in the largest index.
  auto indexes = sub->getIndexes(0, 3 * 3600);
  auto output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "3600.0, 3600.1, 3600.2");

  // Restrict range to "most specific", which is an index by 10.
  indexes = sub->getIndexes(0, 5);
  output = boost::algorithm::join(indexes, ", ");
  // The order 10, 0th index include results with t = [0, 10).
  EXPECT_EQ(output, "10.0");

  // Get a mix of indexes for the lower bounding.
  indexes = sub->getIndexes(2, (3 * 3600));
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "10.0, 10.1, 3600.1, 3600.2, 60.1");

  // Rare, but test ONLY intermediate indexes.
  // Provide an optional third parameter to getIndexes: 1 = 10,(60),3600.
  indexes = sub->getIndexes(2, (3 * 3600), 1);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "60.0, 60.1, 60.120, 60.60");

  // Add specific indexes to the upper bound.
  status = sub->testAdd((2 * 3600) + 11);
  status = sub->testAdd((2 * 3600) + 61);
  indexes = sub->getIndexes(2 * 3600, (2 * 3600) + 62);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "10.726, 60.120");

  // Request specific lower and upper bounding.
  indexes = sub->getIndexes(2, (2 * 3600) + 62);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "10.0, 10.1, 10.726, 3600.1, 60.1, 60.120");
}

TEST_F(EventsDatabaseTests, test_record_range) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();

  // Search within a specific record range.
  auto indexes = sub->getIndexes(0, 10);
  auto records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 2U); // 1, 2

  // Search within a large bound.
  indexes = sub->getIndexes(3, 3601);
  // This will include the 0-10 bucket meaning 1, 2 will show up.
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 5U); // 1, 2, 11, 61, 3601

  // Get all of the records.
  indexes = sub->getIndexes(0, 3 * 3600);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 8U); // 1, 2, 11, 61, 3601, 7201, 7211, 7261

  // stop = 0 is an alias for everything.
  indexes = sub->getIndexes(0, 0);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 8U);
}

TEST_F(EventsDatabaseTests, test_record_expiration) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();

  // No expiration
  auto indexes = sub->getIndexes(0, 5000);
  auto records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 5U); // 1, 2, 11, 61, 3601

  sub->expire_events_ = true;
  sub->expire_time_ = 10;
  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 3U); // 11, 61, 3601

  indexes = sub->getIndexes(0, 5000, 0);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 3U); // 11, 61, 3601

  indexes = sub->getIndexes(0, 5000, 1);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 3U); // 11, 61, 3601

  indexes = sub->getIndexes(0, 5000, 2);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 3U); // 11, 61, 3601

  // Check that get/deletes did not act on cache.
  // This implies that RocksDB is flushing the requested delete records.
  sub->expire_time_ = 0;
  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(records.size(), 3U); // 11, 61, 3601
}

TEST_F(EventsDatabaseTests, test_gentable) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  ASSERT_EQ(sub->optimize_time_, 0U);
  ASSERT_EQ(sub->expire_time_, 0U);

  sub->testAdd(getUnixTime() - 1);
  sub->testAdd(getUnixTime());
  sub->testAdd(getUnixTime() + 1);

  // Test the expire workflow by creating a short expiration time.
  FLAGS_events_expiry = 10;

  std::vector<std::string> keys;
  scanDatabaseKeys("events", keys);
  EXPECT_GT(keys.size(), 10U);

  // Perform a "select" equivalent.
  QueryContext context;
  auto results = sub->genTable(context);
  // Expect all non-expired results: 11, +
  EXPECT_EQ(results.size(), 9U);
  // The expiration time is now - events_expiry.
  EXPECT_GT(sub->expire_time_, getUnixTime() - (FLAGS_events_expiry * 2));
  EXPECT_LT(sub->expire_time_, getUnixTime());

  results = sub->genTable(context);
  EXPECT_EQ(results.size(), 3U);

  results = sub->genTable(context);
  EXPECT_EQ(results.size(), 3U);

  keys.clear();
  scanDatabaseKeys("events", keys);
  EXPECT_LT(keys.size(), 30U);
}
}
