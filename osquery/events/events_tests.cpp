// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include "osquery/events.h"

namespace osquery {

class EventsTests : public testing::Test {
 protected:
  virtual void SetUp() { ef = EventFactory::getInstance(); }

  virtual void TearDown() { ef->deregisterEventTypes(); }

  std::shared_ptr<EventFactory> ef;
};

TEST_F(EventsTests, test_singleton) {
  auto one = EventFactory::getInstance();
  auto two = EventFactory::getInstance();
  EXPECT_EQ(one, two);
}

class BasicEventType : public EventType {
  DECLARE_EVENTTYPE(BasicEventType, MonitorContext, EventContext);
};

class FakeBasicEventType : public EventType {
  DECLARE_EVENTTYPE(FakeBasicEventType, MonitorContext, EventContext);
};

TEST_F(EventsTests, test_register_event_type) {
  Status status;

  // A caller may register an event type using the class template.
  status = EventFactory::registerEventType<BasicEventType>();
  EXPECT_TRUE(status.ok());

  // May also register the event_type instance
  auto event_type_instance = std::make_shared<FakeBasicEventType>();
  status = EventFactory::registerEventType(event_type_instance);
  EXPECT_TRUE(status.ok());

  // May NOT register without subclassing, enforced at compile time.
}

TEST_F(EventsTests, test_create_event_type) {
  Status status;

  status = EventFactory::registerEventType<BasicEventType>();
  EXPECT_TRUE(status.ok());

  // Do not register the same event type twice.
  status = EventFactory::registerEventType<BasicEventType>();
  EXPECT_FALSE(status.ok());

  // Make sure only the first event type was recorded.
  EXPECT_EQ(EventFactory::numEventTypes(), 1);
}

TEST_F(EventsTests, test_create_monitor) {
  Status status;

  EventFactory::registerEventType<BasicEventType>();

  // Make sure a monitor cannot be added for a non-existent event type.
  // Note: It normally would not make sense to create a blank monitor.
  auto monitor = Monitor::create();
  status = EventFactory::addMonitor("FakeBasicEventType", monitor);
  EXPECT_FALSE(status.ok());

  // In this case we can still add a blank monitor to an existing event type.
  status = EventFactory::addMonitor("BasicEventType", monitor);
  EXPECT_TRUE(status.ok());

  // Make sure the monitor is added.
  EXPECT_EQ(EventFactory::numMonitors("BasicEventType"), 1);
}

TEST_F(EventsTests, test_multiple_monitors) {
  Status status;

  EventFactory::registerEventType<BasicEventType>();

  auto monitor = Monitor::create();
  status = EventFactory::addMonitor("BasicEventType", monitor);
  status = EventFactory::addMonitor("BasicEventType", monitor);

  EXPECT_EQ(EventFactory::numMonitors("BasicEventType"), 2);
}

struct TestMonitorContext : public MonitorContext {
  int smallest;
};

class TestEventType : public EventType {
  DECLARE_EVENTTYPE(TestEventType, TestMonitorContext, EventContext);

 public:
  void setUp() { smallest_ever_ += 1; }

  void configure() {
    int smallest_monitor = smallest_ever_;

    configure_run = true;
    for (const auto& monitor : monitors_) {
      auto monitor_context = getMonitorContext(monitor->context);
      if (smallest_monitor > monitor_context->smallest) {
        smallest_monitor = monitor_context->smallest;
      }
    }

    smallest_ever_ = smallest_monitor;
  }

  void tearDown() { smallest_ever_ += 1; }

  TestEventType() : EventType() {
    smallest_ever_ = 0;
    configure_run = false;
  }

  // Custom methods do not make sense, but for testing it exists.
  int getTestValue() { return smallest_ever_; }

 public:
  bool configure_run;

 private:
  int smallest_ever_;
};

TEST_F(EventsTests, test_create_custom_event_type) {
  Status status;

  status = EventFactory::registerEventType<BasicEventType>();
  auto test_event_type = std::make_shared<TestEventType>();
  status = EventFactory::registerEventType(test_event_type);

  // These event types have unique event type IDs
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(EventFactory::numEventTypes(), 2);

  // Make sure the setUp function was called.
  EXPECT_EQ(test_event_type->getTestValue(), 1);
}

TEST_F(EventsTests, test_custom_monitor) {
  Status status;

  // Step 1, register event type
  auto event_type = std::make_shared<TestEventType>();
  status = EventFactory::registerEventType(event_type);

  // Step 2, create and configure a monitor context
  auto monitor_context = std::make_shared<TestMonitorContext>();
  monitor_context->smallest = -1;

  // Step 3, add the monitor to the event type
  status = EventFactory::addMonitor("TestEventType", monitor_context);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(event_type->numMonitors(), 1);

  // The event type must run configure for each added monitor.
  EXPECT_TRUE(event_type->configure_run);
  EXPECT_EQ(event_type->getTestValue(), -1);
}

TEST_F(EventsTests, test_tear_down) {
  Status status;

  auto event_type = std::make_shared<TestEventType>();
  status = EventFactory::registerEventType(event_type);

  // Make sure set up incremented the test value.
  EXPECT_EQ(event_type->getTestValue(), 1);

  status = EventFactory::deregisterEventType("TestEventType");
  EXPECT_TRUE(status.ok());

  // Make sure tear down inremented the test value.
  EXPECT_EQ(event_type->getTestValue(), 2);

  // Once more, now deregistering all event types.
  status = EventFactory::registerEventType(event_type);
  EXPECT_EQ(event_type->getTestValue(), 3);

  status = EventFactory::deregisterEventTypes();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(event_type->getTestValue(), 4);

  // Make sure the factory state represented.
  EXPECT_EQ(EventFactory::numEventTypes(), 0);
}

static int kBellHathTolled = 0;

Status TestTheeCallback(EventContextRef context, bool reserved) {
  kBellHathTolled += 1;
  return Status(0, "OK");
}

TEST_F(EventsTests, test_fire_event) {
  Status status;

  auto event_type = std::make_shared<BasicEventType>();
  status = EventFactory::registerEventType(event_type);

  auto monitor = Monitor::create();
  monitor->callback = TestTheeCallback;
  status = EventFactory::addMonitor("BasicEventType", monitor);

  // The event context creation would normally happen in the event type.
  auto ec = event_type->createEventContext();
  event_type->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 1);

  auto second_monitor = Monitor::create();
  status = EventFactory::addMonitor("BasicEventType", second_monitor);

  // Now there are two monitors (one sans callback).
  event_type->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 2);

  // Now both monitors have callbacks.
  second_monitor->callback = TestTheeCallback;
  event_type->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 4);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
