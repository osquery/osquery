// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include "osquery/events.h"
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
  DECLARE_EVENTMODULE(FakeEventSubscriber, FakeEventType);

 public:
  Status testAdd(int i) {
    Row r;
    r["testing"] = "hello from space";
    return add(r, i);
  }
};

class FakeEventType : public EventType {
  DECLARE_EVENTTYPE(FakeEventType, MonitorContext, EventContext);
};

class AnotherFakeEventSubscriber : public EventSubscriber {
  DECLARE_EVENTMODULE(AnotherFakeEventSubscriber, FakeEventType);
};

TEST_F(EventsDatabaseTests, test_event_module_id) {
  auto fake_event_module = FakeEventSubscriber::getInstance();
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
  Row r;
  r["testing"] = std::string("hello from space");
  size_t event_time = 10;

  auto fake_event_module = FakeEventSubscriber::getInstance();
  auto status = fake_event_module->testAdd(1);
  EXPECT_TRUE(status.ok());
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  int status = RUN_ALL_TESTS();
  boost::filesystem::remove_all(kTestingEventsDBPath);
  return status;
}
