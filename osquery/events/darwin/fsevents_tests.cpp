/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/thread.hpp>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/events/darwin/fsevents.h"

namespace osquery {

const std::string kRealTestPath = "/private/tmp/osquery-fsevents-trigger";
int kMaxEventLatency = 3000;

class FSEventsTests : public testing::Test {
 protected:
  void TearDown() { boost::filesystem::remove_all(kRealTestPath); }

  void StartEventLoop() {
    event_pub_ = std::make_shared<FSEventsEventPublisher>();
    EventFactory::registerEventPublisher(event_pub_);
    FILE* fd = fopen(kRealTestPath.c_str(), "w");
    fclose(fd);

    temp_thread_ = boost::thread(EventFactory::run, "fsevents");
  }

  void EndEventLoop() {
    while (!event_pub_->hasStarted()) {
      ::usleep(20);
    }
    EventFactory::end();
  }

  void WaitForStream(int max) {
    int delay = 0;
    while (delay < max * 1000) {
      if (event_pub_->isStreamRunning()) {
        return;
      }
      ::usleep(50);
      delay += 50;
    }
  }

  bool WaitForEvents(int max, int num_events = 0) {
    int delay = 0;
    while (delay <= max * 1000) {
      if (num_events > 0 && event_pub_->numEvents() >= num_events) {
        return true;
      } else if (num_events == 0 && event_pub_->numEvents() > 0) {
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

  std::shared_ptr<FSEventsEventPublisher> event_pub_;
  boost::thread temp_thread_;
};

TEST_F(FSEventsTests, test_register_event_pub) {
  auto pub = std::make_shared<FSEventsEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventPublishers(), 1);
  status = EventFactory::deregisterEventPublisher("fsevents");
  EXPECT_TRUE(status.ok());
}

TEST_F(FSEventsTests, test_fsevents_add_subscription_missing_path) {
  auto pub = std::make_shared<FSEventsEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  // This subscription path is fake, and will succeed!
  auto mc = std::make_shared<FSEventsSubscriptionContext>();
  mc->path = "/this/path/is/fake";

  auto subscription = Subscription::create("TestSubscriber", mc);
  auto status = EventFactory::addSubscription("fsevents", subscription);
  EXPECT_TRUE(status.ok());
  EventFactory::deregisterEventPublisher("fsevents");
}

TEST_F(FSEventsTests, test_fsevents_add_subscription_success) {
  auto event_pub = std::make_shared<FSEventsEventPublisher>();
  EventFactory::registerEventPublisher(event_pub);

  // This subscription path *should* be real.
  auto mc = std::make_shared<FSEventsSubscriptionContext>();
  mc->path = "/";

  auto subscription = Subscription::create("TestSubscriber", mc);
  auto status = EventFactory::addSubscription("fsevents", subscription);
  EXPECT_TRUE(status.ok());

  // Make sure configure was called.
  size_t num_paths = event_pub->numSubscriptionedPaths();
  EXPECT_EQ(num_paths, 1);

  // A duplicate subscription will work.
  auto mc_dup = std::make_shared<FSEventsSubscriptionContext>();
  mc_dup->path = "/";
  auto subscription_dup = Subscription::create("TestSubscriber", mc_dup);
  status = EventFactory::addSubscription("fsevents", subscription_dup);
  EXPECT_TRUE(status.ok());

  // But the paths with be deduped when the event type reconfigures.
  num_paths = event_pub->numSubscriptionedPaths();
  EXPECT_EQ(num_paths, 1);
  EventFactory::deregisterEventPublisher("fsevents");
}

TEST_F(FSEventsTests, test_fsevents_run) {
  // Assume event type is registered.
  event_pub_ = std::make_shared<FSEventsEventPublisher>();
  EventFactory::registerEventPublisher(event_pub_);

  // Create a subscriptioning context
  auto mc = std::make_shared<FSEventsSubscriptionContext>();
  mc->path = kRealTestPath;
  EventFactory::addSubscription("fsevents", Subscription::create("TestSubscriber", mc));

  // Create an event loop thread (similar to main)
  boost::thread temp_thread(EventFactory::run, "fsevents");
  EXPECT_TRUE(event_pub_->numEvents() == 0);

  // Cause an fsevents event(s) by writing to the watched path.
  CreateEvents();

  // Wait for the thread's run loop to select.
  WaitForEvents(kMaxEventLatency);

  EXPECT_TRUE(event_pub_->numEvents() > 0);
  EventFactory::end();
}

class TestFSEventsEventSubscriber
    : public EventSubscriber<FSEventsEventPublisher> {
  DECLARE_SUBSCRIBER("TestFSEventsEventSubscriber");

 public:
  Status init() { callback_count_ = 0; return Status(0, "OK"); }
  Status SimpleCallback(const FSEventsEventContextRef& ec,
                        const void* user_data) {
    callback_count_ += 1;
    return Status(0, "OK");
  }

  SCRef GetSubscription(uint32_t mask = 0) {
    auto sc = createSubscriptionContext();
    sc->path = kRealTestPath;
    sc->mask = mask;
    return sc;
  }

  Status Callback(const FSEventsEventContextRef& ec, const void* user_data) {
    // The following comments are an example Callback routine.
    // Row r;
    // r["action"] = ec->action;
    // r["path"] = ec->path;

    // Normally would call Add here.
    actions_.push_back(ec->action);
    callback_count_ += 1;
    return Status(0, "OK");
  }

  void WaitForEvents(int max) {
    int delay = 0;
    while (delay < max * 1000) {
      if (callback_count_ > 0) {
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

  // Simulate registering an event subscriber.
  auto sub = std::make_shared<TestFSEventsEventSubscriber>();
  auto status = sub->init();

  // Create a subscriptioning context, note the added Event to the symbol
  auto sc = sub->GetSubscription(0);
  sub->subscribe(&TestFSEventsEventSubscriber::SimpleCallback, sc, nullptr);
  CreateEvents();

  // This time wait for the callback.
  sub->WaitForEvents(kMaxEventLatency);

  // Make sure our expected event fired (aka subscription callback was called).
  EXPECT_TRUE(sub->callback_count_ > 0);
  EndEventLoop();
}

TEST_F(FSEventsTests, test_fsevents_event_action) {
  // Assume event type is registered.
  StartEventLoop();

  // Simulate registering an event subscriber.
  auto sub = std::make_shared<TestFSEventsEventSubscriber>();
  auto status = sub->init();

  auto sc = sub->GetSubscription(0);
  sub->subscribe(&TestFSEventsEventSubscriber::Callback, sc, nullptr);
  CreateEvents();
  sub->WaitForEvents(kMaxEventLatency);

  // Make sure the fsevents action was expected.
  EXPECT_TRUE(sub->actions_.size() > 0);
  if (sub->actions_.size() > 1) {
    EXPECT_EQ(sub->actions_[0], "UPDATED");
  }
  EndEventLoop();
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
