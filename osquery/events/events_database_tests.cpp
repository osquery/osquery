// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/tables.h>

#include "osquery/core/test_util.h"

const std::string kTestingEventsDBPath = "/tmp/rocksdb-osquery-testevents";

namespace osquery {

class EventsDatabaseTests : public ::testing::Test {
 public:
  void SetUp() {
    // Setup a testing DB instance
    DBHandle::getInstanceAtPath(kTestingEventsDBPath);
  }
};

class FakeEventSubscriber : public EventSubscriber {
  DECLARE_EVENTSUBSCRIBER(FakeEventSubscriber, FakeEventPublisher);

 public:
  /// Add a fake event at time t
  Status testAdd(int t) {
    Row r;
    r["testing"] = "hello from space";
    return add(r, t);
  }
};

class FakeEventPublisher : public EventPublisher {
  DECLARE_EVENTPUBLISHER(FakeEventPublisher, SubscriptionContext, EventContext);
};

class AnotherFakeEventSubscriber : public EventSubscriber {
  DECLARE_EVENTSUBSCRIBER(AnotherFakeEventSubscriber, FakeEventPublisher);
};

TEST_F(EventsDatabaseTests, test_event_module_id) {
  auto fake_event_module = FakeEventSubscriber::getInstance();
  fake_event_module->doNotExpire();
  // Not normally available outside of EventSubscriber->Add().
  auto event_id1 = fake_event_module->getEventID();
  EXPECT_EQ(event_id1, "1");
  auto event_id2 = fake_event_module->getEventID();
  EXPECT_EQ(event_id2, "2");
}

TEST_F(EventsDatabaseTests, test_unique_event_module_id) {
  auto fake_event_module = FakeEventSubscriber::getInstance();
  auto another_fake_event_module = AnotherFakeEventSubscriber::getInstance();
  // Not normally available outside of EventSubscriber->Add().
  auto event_id1 = fake_event_module->getEventID();
  EXPECT_EQ(event_id1, "3");
  auto event_id2 = another_fake_event_module->getEventID();
  EXPECT_EQ(event_id2, "1");
}

TEST_F(EventsDatabaseTests, test_event_add) {
  auto fake_event_module = FakeEventSubscriber::getInstance();
  auto status = fake_event_module->testAdd(1);
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsDatabaseTests, test_record_indexing) {
  auto fake_event_module = FakeEventSubscriber::getInstance();
  auto status = fake_event_module->testAdd(2);
  status = fake_event_module->testAdd(11);
  status = fake_event_module->testAdd(61);
  status = fake_event_module->testAdd((1 * 3600) + 1);
  status = fake_event_module->testAdd((2 * 3600) + 1);

  // An "all" range, will pick up everything in the largest index.
  auto indexes = fake_event_module->getIndexes(0, 3 * 3600);
  auto output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "3600.0, 3600.1, 3600.2");

  // Restrict range to "most specific".
  indexes = fake_event_module->getIndexes(0, 5);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "10.0");

  // Get a mix of indexes for the lower bounding.
  indexes = fake_event_module->getIndexes(2, (3 * 3600));
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "3600.1, 3600.2, 60.1, 10.0, 10.1");

  // Rare, but test ONLY intermediate indexes.
  indexes = fake_event_module->getIndexes(2, (3 * 3600), 1);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "60.0, 60.1, 60.60, 60.120");

  // Add specific indexes to the upper bound.
  status = fake_event_module->testAdd((2 * 3600) + 11);
  status = fake_event_module->testAdd((2 * 3600) + 61);
  indexes = fake_event_module->getIndexes(2 * 3600, (2 * 3600) + 62);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "60.120, 10.726");

  // Request specific lower and upper bounding.
  indexes = fake_event_module->getIndexes(2, (2 * 3600) + 62);
  output = boost::algorithm::join(indexes, ", ");
  EXPECT_EQ(output, "3600.1, 60.1, 60.120, 10.0, 10.1, 10.726");
}

TEST_F(EventsDatabaseTests, test_record_range) {
  auto fake_event_module = FakeEventSubscriber::getInstance();

  // Search within a specific record range.
  auto indexes = fake_event_module->getIndexes(0, 10);
  auto records = fake_event_module->getRecords(indexes);
  EXPECT_EQ(records.size(), 2); // 1, 2

  // Search within a large bound.
  indexes = fake_event_module->getIndexes(3, 3601);
  // This will include the 0-10 bucket meaning 1, 2 will show up.
  records = fake_event_module->getRecords(indexes);
  EXPECT_EQ(records.size(), 5); // 1, 2, 11, 61, 3601

  // Get all of the records.
  indexes = fake_event_module->getIndexes(0, 3 * 3600);
  records = fake_event_module->getRecords(indexes);
  EXPECT_EQ(records.size(), 8); // 1, 2, 11, 61, 3601, 7201, 7211, 7261

  // stop = 0 is an alias for everything.
  indexes = fake_event_module->getIndexes(0, 0);
  records = fake_event_module->getRecords(indexes);
  EXPECT_EQ(records.size(), 8);
}

TEST_F(EventsDatabaseTests, test_record_expiration) {
  auto fake_event_module = FakeEventSubscriber::getInstance();

  // No expiration
  auto indexes = fake_event_module->getIndexes(0, 60);
  auto records = fake_event_module->getRecords(indexes);
  EXPECT_EQ(records.size(), 3); // 1, 2, 11

  fake_event_module->expire_events_ = true;
  fake_event_module->expire_time_ = 10;
  indexes = fake_event_module->getIndexes(0, 60);
  records = fake_event_module->getRecords(indexes);
  EXPECT_EQ(records.size(), 1); // 11
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  int status = RUN_ALL_TESTS();
  boost::filesystem::remove_all(kTestingEventsDBPath);
  return status;
}
