/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <memory>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/sql/row.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/events/events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/time.h>

namespace osquery {

static TableRows genRows(EventSubscriberPlugin* sub) {
  auto vtc = std::make_shared<VirtualTableContent>();
  QueryContext context(vtc);
  RowGenerator::pull_type generator(std::bind(&EventSubscriberPlugin::genTable,
                                              sub,
                                              std::placeholders::_1,
                                              std::move(context)));

  TableRows results;
  if (!generator) {
    return results;
  }

  while (generator) {
    results.push_back(generator.get());
    generator();
  }
  return results;
}

DECLARE_uint64(events_expiry);
DECLARE_uint64(events_max);
DECLARE_bool(events_optimize);

class EventsDatabaseTests : public ::testing::Test {
  void SetUp() override {
    registryAndPluginInit();
    initDatabasePluginForTesting();

    RegistryFactory::get().registry("config_parser")->setUp();
    optimize_ = FLAGS_events_optimize;
    FLAGS_events_optimize = false;

    std::vector<std::string> event_keys;
    scanDatabaseKeys(kEvents, event_keys);
    for (const auto& key : event_keys) {
      deleteDatabaseValue(kEvents, key);
    }
  }

  void TearDown() override {
    FLAGS_events_optimize = optimize_;
  }

 private:
  bool optimize_;
};

class DBFakeEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {
  DECLARE_PUBLISHER("DBFakePublisher");
};

class DBFakeEventSubscriber : public EventSubscriber<DBFakeEventPublisher> {
 public:
  DBFakeEventSubscriber() {
    setName("DBFakeSubscriber");
    setEventsMax(FLAGS_events_max);
    setEventsExpiry(FLAGS_events_expiry);
  }

  /// Add num_of_events fake events at time t
  Status testAdd(time_t t, size_t num_of_events = 1) {
    auto indexes = getIndexes(0, t);
    auto records = getRecords(indexes);
    const size_t old_records_size = records.size();

    Row r;
    r["testing"] = "hello from space";
    r["time"] = INTEGER(t);
    r["uptime"] = INTEGER(10);

    std::vector<Row> row_list;
    for (size_t i = 0U; i < num_of_events; i++) {
      row_list.push_back(r);
    }

    auto status = addBatch(row_list, t);
    if (!status.ok()) {
      return Status::failure(
          "Failed to save the batch to the database, with error: " +
          status.getMessage());
    }

    indexes = getIndexes(0, t);
    records = getRecords(indexes);

    if (records.size() != row_list.size() + old_records_size) {
      return Status::failure("We expected " + std::to_string(row_list.size()) +
                             " records but only " +
                             std::to_string(records.size()) + " were found!");
    }

    return Status::success();
  }

  uint64_t getEventsMax() override {
    return max_;
  }

  void setEventsMax(uint64_t max) {
    max_ = max;
  }

  uint64_t getEventsExpiry() override {
    return expiry_;
  }

  void setEventsExpiry(uint64_t expiry) {
    expiry_ = expiry;
  }

 private:
  uint64_t max_;

  uint64_t expiry_;
};

TEST_F(EventsDatabaseTests, test_event_module_id) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  sub->doNotExpire();

  // Not normally available outside of EventSubscriber->Add().
  auto event_id1 = sub->getEventID();
  EXPECT_EQ(event_id1, "0000000001");
  auto event_id2 = sub->getEventID();
  EXPECT_EQ(event_id2, "0000000002");
}

TEST_F(EventsDatabaseTests, test_event_add) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(1);
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsDatabaseTests, test_event_add_batch) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(1, 10);
  EXPECT_TRUE(status.ok()) << status.getMessage();
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
  EXPECT_EQ("60.0, 60.1, 60.60, 60.120", output);

  // Restrict range to "most specific", which is an index by 10.
  indexes = sub->getIndexes(0, 5);
  output = boost::algorithm::join(indexes, ", ");
  // The order 10, 0th index include results with t = [0, 10).
  EXPECT_EQ("60.0", output);

  // Add specific indexes to the upper bound.
  status = sub->testAdd((2 * 3600) + 11);
  status = sub->testAdd((2 * 3600) + 61);
  indexes = sub->getIndexes(2 * 3600, (2 * 3600) + 62);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ("60.120, 60.121", output);

  // Request specific lower and upper bounding.
  indexes = sub->getIndexes(2, (2 * 3600) + 62);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ("60.0, 60.1, 60.60, 60.120, 60.121", output);
}

TEST_F(EventsDatabaseTests, test_record_range) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(1);
  status = sub->testAdd(2);
  status = sub->testAdd(11);
  status = sub->testAdd(61);
  status = sub->testAdd((1 * 3600) + 1);
  status = sub->testAdd((2 * 3600) + 1);

  // Search within a specific record range.
  auto indexes = sub->getIndexes(0, 10);
  EXPECT_EQ(1U, indexes.size());
  auto records = sub->getRecords(indexes);
  // This will return 3 results, ::get filters records by an absolute range.
  EXPECT_EQ(3U, records.size()); // 1, 2, 11

  // Search within a large bound.
  indexes = sub->getIndexes(3, 3601);
  // This will include the 0-10 bucket meaning 1, 2 will show up.
  records = sub->getRecords(indexes);
  EXPECT_EQ(5U, records.size()); // 1, 2, 11, 61, 3601

  // Get all of the records.
  indexes = sub->getIndexes(0, 3 * 3600);
  records = sub->getRecords(indexes);
  EXPECT_EQ(6U, records.size()); // 1, 2, 11, 61, 3601, 7201

  // stop = 0 is an alias for everything.
  indexes = sub->getIndexes(0, 0);
  records = sub->getRecords(indexes);
  EXPECT_EQ(6U, records.size());

  for (size_t j = 0; j < 30; j++) {
    // 110 is 10 below an index (60.2).
    sub->testAdd(110 + static_cast<int>(j));
  }

  indexes = sub->getIndexes(110, 0);
  auto output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ("60.1, 60.2, 60.60, 60.120", output);
  records = sub->getRecords(indexes);
  EXPECT_EQ(33U, records.size()); // (61) 110 - 139 + 3601, 7201
}

TEST_F(EventsDatabaseTests, test_record_corruption) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();

  std::string corrupted_index = "60.25440186";
  std::string key =
      "records.DBFakePublisher.DBFakeSubscriber." + corrupted_index;
  std::string value =
      "0002985852:1526411162,0002985853:1526411162,00??E/"
      "?:1526411170,0002985912:1526411170,0002??E/"
      "?526411178,0002985921:1526411178,0002985922:1526411178";

  // Set some corrupted values in the DB
  auto s = setDatabaseValue(kEvents, key, value);
  auto records = sub->getRecords({corrupted_index});

  // We should gracefully skip over corrupted record entries
  EXPECT_EQ(6U, records.size());
}

TEST_F(EventsDatabaseTests, test_record_expiration) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(1);
  status = sub->testAdd(2);
  status = sub->testAdd(11);
  status = sub->testAdd(61);
  status = sub->testAdd((1 * 3600) + 1);
  status = sub->testAdd((2 * 3600) + 1);

  // No expiration
  auto indexes = sub->getIndexes(0, 5000);
  auto records = sub->getRecords(indexes);
  EXPECT_EQ(5U, records.size()); // 1, 2, 11, 61, 3601

  sub->expire_events_ = true;
  sub->expire_time_ = 10;
  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(3U, records.size()); // 11, 61, 3601

  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(3U, records.size()); // 11, 61, 3601

  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(3U, records.size()); // 11, 61, 3601

  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(3U, records.size()); // 11, 61, 3601

  // Check that get/deletes did not act on cache.
  // This implies that RocksDB is flushing the requested delete records.
  sub->expire_time_ = 0;
  indexes = sub->getIndexes(0, 5000);
  records = sub->getRecords(indexes);
  EXPECT_EQ(3U, records.size()); // 11, 61, 3601
}

TEST_F(EventsDatabaseTests, test_gentable) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  auto status = sub->testAdd(1);
  status = sub->testAdd(2);
  status = sub->testAdd(11);
  status = sub->testAdd(61);
  status = sub->testAdd((1 * 3600) + 1);
  status = sub->testAdd((2 * 3600) + 1);

  ASSERT_EQ(0U, sub->optimize_time_);
  ASSERT_EQ(0U, sub->expire_time_);
  ASSERT_EQ(0U, sub->min_expiration_);

  auto t = getUnixTime();
  sub->testAdd(t - 1);
  sub->testAdd(t);
  sub->testAdd(t + 1);

  // Test the expire workflow by creating a short expiration time.
  sub->setEventsExpiry(10);

  std::vector<std::string> keys;
  scanDatabaseKeys("events", keys);
  // 9 data records, 1 eid counter, 3 indexes, 15 index records.
  // Depending on the moment, an additional 3 indexes may be introduced.
  EXPECT_LE(16U, keys.size());

  // Perform a "select" equivalent.
  auto results = genRows(sub.get());

  // Expect all non-expired results: 11, +
  EXPECT_EQ(9U, results.size());
  // The expiration time is now - events_expiry +/ 60.
  EXPECT_LT(t - (sub->getEventsExpiry() * 2), sub->expire_time_ + 60);
  EXPECT_GT(t, sub->expire_time_);
  // The optimize time will not be changed.
  ASSERT_EQ(0U, sub->optimize_time_);

  results = genRows(sub.get());
  EXPECT_EQ(3U, results.size());

  results = genRows(sub.get());
  EXPECT_EQ(3U, results.size());

  keys.clear();
  scanDatabaseKeys("events", keys);
  EXPECT_LE(6U, keys.size());
}

TEST_F(EventsDatabaseTests, test_optimize) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  for (size_t i = 800; i < 800 + 10; ++i) {
    sub->testAdd(i);
  }

  // Lie about the tool type to enable optimizations.
  auto default_type = getToolType();
  setToolType(ToolType::DAEMON);
  FLAGS_events_optimize = true;

  // Must also define an executing query.
  setDatabaseValue(kPersistentSettings, kExecutingQuery, "events_db_test");

  auto t = getUnixTime();
  auto results = genRows(sub.get());
  EXPECT_EQ(10U, results.size());
  // Optimization will set the time NOW as the minimum event time.
  // Thus it is not possible to set event in past.
  EXPECT_GE(sub->optimize_time_ + 100, t);
  EXPECT_LE(sub->optimize_time_ - 100, t);
  // The last EID returned will also be stored for duplication checks.
  EXPECT_EQ(10U, sub->optimize_eid_);

  for (uint64_t i = t + 800; i < t + 800 + 10; ++i) {
    sub->testAdd(i);
  }

  results = genRows(sub.get());
  EXPECT_EQ(10U, results.size());

  // The optimize time should have been written to the database.
  // It should be the same as the current (relative) optimize time.
  std::string content;
  getDatabaseValue("events", "optimize.events_db_test", content);
  EXPECT_EQ(std::to_string(sub->optimize_time_), content);

  // Restore the tool type.
  setToolType(default_type);
}

TEST_F(EventsDatabaseTests, test_expire_check) {
  auto sub = std::make_shared<DBFakeEventSubscriber>();
  // Set the max number of buffered events to something reasonably small.
  sub->setEventsMax(50);
  size_t t = 10000;

  // We are still at the mercy of the opaque EVENTS_CHECKPOINT define.
  for (size_t x = 0; x < 3; x++) {
    size_t num_events = 256 * x;
    for (size_t i = 0; i < num_events; i++) {
      sub->testAdd(t++);
    }

    // Since events tests are dependent, expect 257 + 3 events.
    auto results = genRows(sub.get());
    if (x == 0) {
      // The first iteration is dependent on previous test state.
      continue;
    }

    // The number of events should remain constant.
    // In practice there may be an event still in the write queue.
    EXPECT_LT(results.size(), 60U);
  }

  // Try again, this time with a scan
  for (size_t k = 0; k < 3; k++) {
    for (size_t x = 0; x < 3; x++) {
      size_t num_events = 256 * x;
      for (size_t i = 0; i < num_events; i++) {
        sub->testAdd(t++);
      }

      // Records hold the event_id + time indexes.
      // Data hosts the event_id + JSON content.
      auto record_key = "records." + sub->dbNamespace();
      auto data_key = "data." + sub->dbNamespace();

      std::vector<std::string> records, datas;
      scanDatabaseKeys(kEvents, records, record_key);
      scanDatabaseKeys(kEvents, datas, data_key);

      EXPECT_LT(records.size(), 20U);
      EXPECT_LT(datas.size(), 60U);
    }
  }
}
} // namespace osquery
