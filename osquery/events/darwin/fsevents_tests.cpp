// Copyright 2004-present Facebook. All Rights Reserved.

#include <stdio.h>

#include <boost/thread.hpp>

#include <gtest/gtest.h>

#include "osquery/events.h"
#include "osquery/events/darwin/fsevents.h"

namespace osquery {

const std::string kRealTestPath = "/private/tmp/osquery-fsevents-trigger";
int kMaxEventLatency = 3000;

class FSEventsTests : public testing::Test {
 protected:
  virtual void TearDown() { EventFactory::deregisterEventTypes(); }

  void StartEventLoop() {
    event_type_ = std::make_shared<FSEventsEventType>();
    EventFactory::registerEventType(event_type_);
    FILE* fd = fopen(kRealTestPath.c_str(), "w");
    fclose(fd);

    temp_thread_ = boost::thread(EventFactory::run, "FSEventsEventType");
  }

  void MonitorAction(uint32_t mask = 0, EventCallback ec = 0) {
    auto mc = std::make_shared<FSEventsMonitorContext>();
    mc->path = kRealTestPath;
    mc->mask = mask;

    EventFactory::addMonitor("FSEventsEventType", mc, ec);
  }

  void WaitForStream(int max) {
    int delay = 0;
    while (delay < max * 1000) {
      if (event_type_->isStreamRunning()) {
        return;
      }
      ::usleep(50);
      delay += 50;
    }
  }

  bool WaitForEvents(int max, int num_events = 0) {
    int delay = 0;
    while (delay <= max * 1000) {
      if (num_events > 0 && event_type_->numEvents() >= num_events) {
        return true;
      } else if (num_events == 0 && event_type_->numEvents() > 0) {
        return true;
      }
      delay += 50;
      ::usleep(50);
    }
    return false;
  }

  void CreateEvents(int num = 1) {
    WaitForStream(kMaxEventLatency);
    for (int i = 0; i < num; ++i) {
      FILE* fd = fopen(kRealTestPath.c_str(), "w");
      fputs("fsevents", fd);
      fclose(fd);
    }
  }

  void EndEventLoop() {
    EventFactory::end();
    event_type_->tearDown();
    temp_thread_.join();
    EventFactory::end(false);
  }

  std::shared_ptr<FSEventsEventType> event_type_;
  boost::thread temp_thread_;
};

TEST_F(FSEventsTests, test_register_event_type) {
  auto status = EventFactory::registerEventType<FSEventsEventType>();
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventTypes(), 1);
}

TEST_F(FSEventsTests, test_fsevents_add_monitor_missing_path) {
  EventFactory::registerEventType<FSEventsEventType>();

  // This monitor path is fake, and will succeed!
  auto mc = std::make_shared<FSEventsMonitorContext>();
  mc->path = "/this/path/is/fake";

  auto monitor = Monitor::create(mc);
  auto status = EventFactory::addMonitor("FSEventsEventType", monitor);
  EXPECT_TRUE(status.ok());
}

TEST_F(FSEventsTests, test_fsevents_add_monitor_success) {
  auto event_type = std::make_shared<FSEventsEventType>();
  EventFactory::registerEventType(event_type);

  // This monitor path *should* be real.
  auto mc = std::make_shared<FSEventsMonitorContext>();
  mc->path = "/";

  auto monitor = Monitor::create(mc);
  auto status = EventFactory::addMonitor("FSEventsEventType", monitor);
  EXPECT_TRUE(status.ok());

  // Make sure configure was called.
  size_t num_paths = event_type->numMonitoredPaths();
  EXPECT_EQ(num_paths, 1);

  // A duplicate monitor will work.
  auto mc_dup = std::make_shared<FSEventsMonitorContext>();
  mc_dup->path = "/";
  auto monitor_dup = Monitor::create(mc_dup);
  status = EventFactory::addMonitor("FSEventsEventType", monitor_dup);
  EXPECT_TRUE(status.ok());

  // But the paths with be deduped when the event type reconfigures.
  num_paths = event_type->numMonitoredPaths();
  EXPECT_EQ(num_paths, 1);
}

TEST_F(FSEventsTests, test_fsevents_run) {
  // Assume event type is registered.
  event_type_ = std::make_shared<FSEventsEventType>();
  EventFactory::registerEventType(event_type_);

  // Create a monitoring context
  auto mc = std::make_shared<FSEventsMonitorContext>();
  mc->path = kRealTestPath;
  EventFactory::addMonitor("FSEventsEventType", Monitor::create(mc));

  // Create an event loop thread (similar to main)
  boost::thread temp_thread(EventFactory::run, "FSEventsEventType");
  EXPECT_TRUE(event_type_->numEvents() == 0);

  // Cause an fsevents event(s) by writing to the watched path.
  CreateEvents();

  // Wait for the thread's run loop to select.
  WaitForEvents(kMaxEventLatency);

  EXPECT_TRUE(event_type_->numEvents() > 0);

  // Cause the thread to tear down.
  EventFactory::end();
  // Call tearDown ourselves before joining.
  event_type_->tearDown();
  temp_thread.join();
  // Reset the event factory state.
  EventFactory::end(false);
}

class TestFSEventsEventModule : public EventModule {
  DECLARE_EVENTMODULE(TestFSEventsEventModule, FSEventsEventType);
  DECLARE_CALLBACK(SimpleCallback, FSEventsEventContext);
  DECLARE_CALLBACK(Callback, FSEventsEventContext);

 public:
  void init() { callback_count_ = 0; }
  Status SimpleCallback(const FSEventsEventContextRef ec) {
    callback_count_ += 1;
    return Status(0, "OK");
  }

  Status Callback(const FSEventsEventContextRef ec) {
    Row r;
    r["action"] = ec->action;
    r["path"] = ec->path;

    // Normally would call Add here.
    actions_.push_back(ec->action);
    callback_count_ += 1;
    return Status(0, "OK");
  }

  static void WaitForEvents(int max) {
    int delay = 0;
    while (delay < max * 1000) {
      if (getInstance()->callback_count_ > 0) {
        return;
      }
      ::usleep(50);
      delay += 50;
    }
  }

 public:
  int callback_count_;
  std::vector<std::string> actions_;
};

TEST_F(FSEventsTests, test_fsevents_fire_event) {
  // Assume event type is registered.
  StartEventLoop();
  TestFSEventsEventModule::getInstance()->init();

  // Create a monitoring context, note the added Event to the symbol
  MonitorAction(0, TestFSEventsEventModule::EventSimpleCallback);

  CreateEvents();

  // This time wait for the callback.
  TestFSEventsEventModule::WaitForEvents(kMaxEventLatency);

  // Make sure our expected event fired (aka monitor callback was called).
  EXPECT_TRUE(TestFSEventsEventModule::getInstance()->callback_count_ > 0);

  // Cause the thread to tear down.
  EndEventLoop();
}

TEST_F(FSEventsTests, test_fsevents_event_action) {
  // Assume event type is registered.
  StartEventLoop();
  TestFSEventsEventModule::getInstance()->init();

  TestFSEventsEventModule::getInstance()->callback_count_ = 0;
  MonitorAction(0, TestFSEventsEventModule::EventCallback);

  CreateEvents();
  TestFSEventsEventModule::WaitForEvents(kMaxEventLatency);

  // Make sure the fsevents action was expected.
  const auto& event_module = TestFSEventsEventModule::getInstance();
  EXPECT_TRUE(event_module->actions_.size() > 0);
  if (event_module->actions_.size() > 1) {
    EXPECT_EQ(event_module->actions_[0], "UPDATED");
  }

  // Cause the thread to tear down.
  EndEventLoop();
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
