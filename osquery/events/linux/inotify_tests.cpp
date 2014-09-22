// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include "osquery/events.h"
#include "osquery/events/linux/inotify.h"

namespace osquery {

class INotifyTests : public testing::Test {
 protected:
  virtual void SetUp() { ef = EventFactory::get(); }

  virtual void TearDown() { EventFactory::deregisterEventTypes(); }

  boost::shared_ptr<EventFactory> ef;
};

TEST_F(INotifyTests, test_register_event_type) {
  Status status;

  status = EventFactory::registerEventType<INotifyEventType>();
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventTypes(), 1);
}

TEST_F(INotifyTests, test_inotify_init) {
  Status status;

  // Handle should not be initialized during ctor.
  auto event_type = boost::make_shared<INotifyEventType>();
  EXPECT_FALSE(event_type->isHandleOpen());

  // Registering the event type initializes inotify.
  EventFactory::registerEventType(event_type);
  EXPECT_TRUE(event_type->isHandleOpen());

  // Similarly deregistering closes the handle.
  EventFactory::deregisterEventTypes();
  EXPECT_FALSE(event_type->isHandleOpen());
}

TEST_F(INotifyTests, test_inotify_add_monitor) {
  Status status;

  EventFactory::registerEventType<INotifyEventType>();

  auto mc = boost::make_shared<INotifyMonitorContext>();
  mc->path = "/this/path/is/fake";

  auto monitor = Monitor::create(mc);
  status = EventFactory::addMonitor("INotifyEventType", monitor);
  EXPECT_TRUE(status.ok());
}

TEST_F(INotifyTests, test_inotify_run) {
  Status status;

  EventFactory::registerEventType<INotifyEventType>();

  auto mc = boost::make_shared<INotifyMonitorContext>();
  mc->path = "/this/path/is/fake";
  EventFactory::addMonitor("INotifyEventType", Monitor::create(mc));

  // Need a thread that touches the file path above
  // status = EventFactory::run("INotifyEventType");
  // EXPECT_TRUE(status.ok());
  EXPECT_TRUE(true);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
