// Copyright 2004-present Facebook. All Rights Reserved.

#include <stdio.h>

#include <boost/thread.hpp>

#include <gtest/gtest.h>

#include "osquery/events.h"
#include "osquery/events/linux/inotify.h"

namespace osquery {

const std::string kRealTestPath = "/tmp/osquery-inotify-trigger";

class INotifyTests : public testing::Test {
 protected:
  virtual void TearDown() { EventFactory::deregisterEventPublishers(); }

  void StartEventLoop() {
    auto event_pub = std::make_shared<INotifyEventPublisher>();
    EventFactory::registerEventPublisher(event_pub);
    FILE* fd = fopen(kRealTestPath.c_str(), "w");
    fclose(fd);

    temp_thread_ = boost::thread(EventFactory::run, "INotifyEventPublisher");
  }

  void MonitorAction(uint32_t mask = 0, EventCallback ec = 0) {
    auto mc = std::make_shared<INotifyMonitorContext>();
    mc->path = kRealTestPath;
    mc->mask = mask;

    EventFactory::addMonitor("INotifyEventPublisher", mc, ec);
  }

  void EndEventLoop() {
    EventFactory::end();
    temp_thread_.join();
    EventFactory::end(false);
  }

  boost::thread temp_thread_;
};

// Helper eager wait function.
bool waitForEvent(int max, int num_events = 0) {
  int step = 50;
  int delay = 0;
  const auto& et = EventFactory::getEventPublisher("INotifyEventPublisher");
  while (delay <= max * 1000) {
    if (num_events > 0 && et->numEvents() >= num_events) {
      return true;
    } else if (num_events == 0 && et->numEvents() > 0) {
      return true;
    }
    delay += step;
    ::usleep(step);
  }
  return false;
}

TEST_F(INotifyTests, test_register_event_pub) {
  auto status = EventFactory::registerEventPublisher<INotifyEventPublisher>();
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventPublishers(), 1);
}

TEST_F(INotifyTests, test_inotify_init) {
  // Handle should not be initialized during ctor.
  auto event_pub = std::make_shared<INotifyEventPublisher>();
  EXPECT_FALSE(event_pub->isHandleOpen());

  // Registering the event type initializes inotify.
  EventFactory::registerEventPublisher(event_pub);
  EXPECT_TRUE(event_pub->isHandleOpen());

  // Similarly deregistering closes the handle.
  EventFactory::deregisterEventPublishers();
  EXPECT_FALSE(event_pub->isHandleOpen());
}

TEST_F(INotifyTests, test_inotify_add_monitor_fail) {
  EventFactory::registerEventPublisher<INotifyEventPublisher>();

  // This monitor path is fake, and will fail
  auto mc = std::make_shared<INotifyMonitorContext>();
  mc->path = "/this/path/is/fake";

  auto monitor = Monitor::create(mc);
  auto status = EventFactory::addMonitor("INotifyEventPublisher", monitor);
  EXPECT_FALSE(status.ok());
}

TEST_F(INotifyTests, test_inotify_add_monitor_success) {
  EventFactory::registerEventPublisher<INotifyEventPublisher>();

  // This monitor path *should* be real.
  auto mc = std::make_shared<INotifyMonitorContext>();
  mc->path = "/";

  auto monitor = Monitor::create(mc);
  auto status = EventFactory::addMonitor("INotifyEventPublisher", monitor);
  EXPECT_TRUE(status.ok());
}

TEST_F(INotifyTests, test_inotify_run) {
  // Assume event type is registered.
  auto event_pub = std::make_shared<INotifyEventPublisher>();
  EventFactory::registerEventPublisher(event_pub);

  // Create a temporary file to watch, open writeable
  FILE* fd = fopen(kRealTestPath.c_str(), "w");

  // Create a monitoring context
  auto mc = std::make_shared<INotifyMonitorContext>();
  mc->path = kRealTestPath;
  EventFactory::addMonitor("INotifyEventPublisher", Monitor::create(mc));

  // Create an event loop thread (similar to main)
  boost::thread temp_thread(EventFactory::run, "INotifyEventPublisher");
  EXPECT_TRUE(event_pub->numEvents() == 0);

  // Cause an inotify event by writing to the watched path.
  fputs("inotify", fd);
  fclose(fd);

  // Wait for the thread's run loop to select.
  waitForEvent(2000);
  EXPECT_TRUE(event_pub->numEvents() > 0);

  // Cause the thread to tear down.
  EventFactory::end();
  temp_thread.join();
  // Reset the event factory state.
  EventFactory::end(false);
}

class TestINotifyEventSubscriber : public EventSubscriber {
  DECLARE_EVENTMODULE(TestINotifyEventSubscriber, INotifyEventPublisher);
  DECLARE_CALLBACK(SimpleCallback, INotifyEventContext);
  DECLARE_CALLBACK(Callback, INotifyEventContext);

 public:
  void init() { callback_count_ = 0; }
  Status SimpleCallback(const INotifyEventContextRef ec) {
    callback_count_ += 1;
    return Status(0, "OK");
  }

  Status Callback(const INotifyEventContextRef ec) {
    Row r;
    r["action"] = ec->action;
    r["path"] = ec->path;

    // Normally would call Add here.
    actions_.push_back(ec->action);
    return Status(0, "OK");
  }

 public:
  int callback_count_;
  std::vector<std::string> actions_;
};

TEST_F(INotifyTests, test_inotify_fire_event) {
  // Assume event type is registered.
  StartEventLoop();

  // Create a monitoring context, note the added Event to the symbol
  MonitorAction(0, TestINotifyEventSubscriber::EventSimpleCallback);

  FILE* fd = fopen(kRealTestPath.c_str(), "w");
  fputs("inotify", fd);
  fclose(fd);
  waitForEvent(2000);

  // Make sure our expected event fired (aka monitor callback was called).
  EXPECT_TRUE(TestINotifyEventSubscriber::getInstance()->callback_count_ > 0);

  // Cause the thread to tear down.
  EndEventLoop();
}

TEST_F(INotifyTests, test_inotify_event_action) {
  // Assume event type is registered.
  StartEventLoop();
  MonitorAction(0, TestINotifyEventSubscriber::EventCallback);

  FILE* fd = fopen(kRealTestPath.c_str(), "w");
  fputs("inotify", fd);
  fclose(fd);
  waitForEvent(2000, 4);

  // Make sure the inotify action was expected.
  EXPECT_EQ(TestINotifyEventSubscriber::getInstance()->actions_.size(), 4);
  EXPECT_EQ(TestINotifyEventSubscriber::getInstance()->actions_[0], "UPDATED");
  EXPECT_EQ(TestINotifyEventSubscriber::getInstance()->actions_[1], "OPENED");
  EXPECT_EQ(TestINotifyEventSubscriber::getInstance()->actions_[2], "UPDATED");
  EXPECT_EQ(TestINotifyEventSubscriber::getInstance()->actions_[3], "UPDATED");

  // Cause the thread to tear down.
  EndEventLoop();
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
