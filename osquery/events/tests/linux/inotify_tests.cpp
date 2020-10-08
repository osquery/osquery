/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <stdio.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/inotify.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/info/tool_type.h>

namespace fs = boost::filesystem;

namespace osquery {
DECLARE_bool(enable_file_events);

const int kMaxEventLatency = 3000;

class INotifyTests : public testing::Test {
  bool enable_file_events_backup{false};

 protected:
  void SetUp() override {
    enable_file_events_backup = FLAGS_enable_file_events;
    FLAGS_enable_file_events = true;

    setToolType(ToolType::TEST);
    registryAndPluginInit();
    initDatabasePluginForTesting();

    // INotify will use data from the config and config parsers.
    Registry::get().registry("config_parser")->setUp();

    // Create a basic path trigger, this is a file path.
    real_test_path =
        fs::weakly_canonical(fs::temp_directory_path() /
                             fs::unique_path("inotify-trigger.%%%%.%%%%"))
            .string();
    // Create a similar directory for embedded paths and directories.
    real_test_dir =
        fs::weakly_canonical(fs::temp_directory_path() /
                             fs::unique_path("inotify-trigger.%%%%.%%%%"))
            .string();

    // Create the embedded paths.
    real_test_dir_path = real_test_dir + "/1";
    real_test_sub_dir = real_test_dir + "/2";
    real_test_sub_dir_path = real_test_sub_dir + "/1";
  }

  void TearDown() override {
    FLAGS_enable_file_events = enable_file_events_backup;

    // End the event loops, and join on the threads.
    removePath(real_test_dir);
    removePath(real_test_path);
  }

  void StartEventLoop() {
    event_pub_ = std::make_shared<INotifyEventPublisher>(true);
    auto status = EventFactory::registerEventPublisher(event_pub_);
    FILE* fd = fopen(real_test_path.c_str(), "w");
    fclose(fd);
    temp_thread_ = std::thread(EventFactory::run, "inotify");
  }

  void StopEventLoop() {
    while (!event_pub_->hasStarted()) {
      ::usleep(20);
    }

    EventFactory::end(true);
    temp_thread_.join();
  }

  void SubscriptionAction(const std::string& path,
                          uint32_t mask = IN_ALL_EVENTS,
                          EventCallback ec = nullptr) {
    auto sc = std::make_shared<INotifySubscriptionContext>();
    sc->path = path;
    sc->mask = mask;

    EventFactory::addSubscription("inotify", "TestSubscriber", sc, ec);
    event_pub_->configure();
  }

  bool WaitForEvents(size_t max, size_t num_events = 0) {
    size_t delay = 0;
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

  void TriggerEvent(const std::string& path) {
    FILE* fd = fopen(path.c_str(), "w");
    fputs("inotify", fd);
    fclose(fd);
  }

  void addMonitor(const std::string& path,
                  uint32_t mask,
                  bool recursive,
                  bool add_watch) {
    auto sc = event_pub_->createSubscriptionContext();
    event_pub_->addMonitor(path, sc, mask, recursive, add_watch);
  }

  void RemoveAll(std::shared_ptr<INotifyEventPublisher>& pub) {
    pub->subscriptions_.clear();
    // Reset monitors.
    std::vector<int> wds;
    for (const auto& path : pub->descriptor_inosubctx_) {
      wds.push_back(path.first);
    }
    for (const auto& wd : wds) {
      pub->removeMonitor(wd, true);
    }
  }

 protected:
  /// Internal state managers: publisher reference.
  std::shared_ptr<INotifyEventPublisher> event_pub_{nullptr};

  /// Internal state managers: event publisher thread.
  std::thread temp_thread_;

  /// Transient paths ./inotify-trigger.
  std::string real_test_path;

  /// Transient paths ./inotify-triggers/.
  std::string real_test_dir;

  /// Transient paths ./inotify-triggers/1.
  std::string real_test_dir_path;

  /// Transient paths ./inotify-triggers/2/.
  std::string real_test_sub_dir;

  /// Transient paths ./inotify-triggers/2/1.
  std::string real_test_sub_dir_path;
};

TEST_F(INotifyTests, test_register_event_pub) {
  auto pub = std::make_shared<INotifyEventPublisher>(true);
  auto status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventPublishers(), 1U);
  // And deregister
  status = EventFactory::deregisterEventPublisher("inotify");
  EXPECT_TRUE(status.ok());
}

TEST_F(INotifyTests, test_inotify_init) {
  // Handle should not be initialized during ctor.
  auto event_pub = std::make_shared<INotifyEventPublisher>(true);
  EXPECT_FALSE(event_pub->isHandleOpen());

  // Registering the event type initializes inotify.
  auto status = EventFactory::registerEventPublisher(event_pub);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(event_pub->isHandleOpen());

  // Similarly deregistering closes the handle.
  EventFactory::deregisterEventPublisher("inotify");
  EXPECT_FALSE(event_pub->isHandleOpen());
}

TEST_F(INotifyTests, test_inotify_add_subscription_missing_path) {
  auto pub = std::make_shared<INotifyEventPublisher>(true);
  EventFactory::registerEventPublisher(pub);

  // This subscription path is fake, and will succeed.
  auto mc = std::make_shared<INotifySubscriptionContext>();
  mc->path = "/this/path/is/fake";

  auto subscription = Subscription::create("TestSubscriber", mc);
  auto status = EventFactory::addSubscription("inotify", subscription);
  EXPECT_TRUE(status.ok());
  EventFactory::deregisterEventPublisher("inotify");
}

TEST_F(INotifyTests, test_inotify_add_subscription_success) {
  auto pub = std::make_shared<INotifyEventPublisher>(true);
  EventFactory::registerEventPublisher(pub);

  // This subscription path *should* be real.
  auto mc = std::make_shared<INotifySubscriptionContext>();
  mc->path = "/";
  mc->mask = IN_ALL_EVENTS;

  auto subscription = Subscription::create("TestSubscriber", mc);
  auto status = EventFactory::addSubscription("inotify", subscription);
  EXPECT_TRUE(status.ok());
  EventFactory::deregisterEventPublisher("inotify");
}

TEST_F(INotifyTests, test_inotify_match_subscription) {
  event_pub_ = std::make_shared<INotifyEventPublisher>(true);
  addMonitor("/etc", IN_ALL_EVENTS, false, false);
  EXPECT_EQ(event_pub_->path_descriptors_.count("/etc"), 1U);
  // This will fail because there is no trailing "/" at the end.
  // The configure component should take care of these paths.
  EXPECT_FALSE(event_pub_->isPathMonitored("/etc/passwd"));
  event_pub_->path_descriptors_.clear();

  // Calling addMonitor the correct way.
  addMonitor("/etc/", IN_ALL_EVENTS, false, false);
  EXPECT_TRUE(event_pub_->isPathMonitored("/etc/passwd"));
  event_pub_->path_descriptors_.clear();

  // Test the matching capability.
  {
    auto sc = event_pub_->createSubscriptionContext();
    sc->path = "/etc";
    event_pub_->monitorSubscription(sc, false);
    EXPECT_EQ(sc->path, "/etc/");
    EXPECT_TRUE(event_pub_->isPathMonitored("/etc/"));
    EXPECT_TRUE(event_pub_->isPathMonitored("/etc/passwd"));
  }

  std::vector<std::string> valid_dirs = {"/etc", "/etc/", "/etc/*"};
  for (const auto& dir : valid_dirs) {
    event_pub_->path_descriptors_.clear();
    auto sc = event_pub_->createSubscriptionContext();
    sc->path = dir;
    event_pub_->monitorSubscription(sc, false);
    auto ec = event_pub_->createEventContext();
    ec->isub_ctx = sc;
    ec->path = "/etc/";
    EXPECT_TRUE(event_pub_->shouldFire(sc, ec));
    ec->path = "/etc/passwd";
    EXPECT_TRUE(event_pub_->shouldFire(sc, ec));
  }

  std::vector<std::string> exclude_paths = {
      "/etc/ssh/%%", "/etc/", "/etc/ssl/openssl.cnf", "/"};
  for (const auto& path : exclude_paths) {
    event_pub_->exclude_paths_.insert(path);
  }

  {
    event_pub_->path_descriptors_.clear();
    auto sc = event_pub_->createSubscriptionContext();
    sc->path = "/etc/%%";
    auto ec = event_pub_->createEventContext();
    ec->isub_ctx = sc;
    ec->path = "/etc/ssh/ssh_config";
    EXPECT_FALSE(event_pub_->shouldFire(sc, ec));
    ec->path = "/etc/passwd";
    EXPECT_FALSE(event_pub_->shouldFire(sc, ec));
    ec->path = "/etc/group";
    EXPECT_FALSE(event_pub_->shouldFire(sc, ec));
    ec->path = "/etc/ssl/openssl.cnf";
    EXPECT_FALSE(event_pub_->shouldFire(sc, ec));
    ec->path = "/etc/ssl/certs/";
    EXPECT_TRUE(event_pub_->shouldFire(sc, ec));
  }
}

class TestINotifyEventSubscriber
    : public EventSubscriber<INotifyEventPublisher> {
 public:
  TestINotifyEventSubscriber() {
    setName("TestINotifyEventSubscriber");
  }

  Status init() override {
    callback_count_ = 0;
    return Status::success();
  }

  Status SimpleCallback(const ECRef& ec, const SCRef& sc) {
    callback_count_ += 1;
    return Status::success();
  }

  Status Callback(const ECRef& ec, const SCRef& sc) {
    // The following comments are an example Callback routine.
    // Row r;
    // r["action"] = ec->action;
    // r["path"] = ec->path;

    // Normally would call Add here.
    callback_count_++;

    WriteLock lock(actions_lock_);
    actions_.push_back(ec->action);
    return Status::success();
  }

  SCRef GetSubscription(const std::string& path,
                        uint32_t mask = IN_ALL_EVENTS) {
    auto mc = createSubscriptionContext();
    mc->path = path;
    mc->mask = mask;
    return mc;
  }

  void WaitForEvents(int max, int num_events = 1) {
    int delay = 0;
    while (delay < max * 1000) {
      if (callback_count_ >= num_events) {
        return;
      }
      ::usleep(50);
      delay += 50;
    }
  }

  std::vector<std::string> actions() {
    WriteLock lock(actions_lock_);
    return actions_;
  }

  int count() {
    return callback_count_;
  }

 public:
  std::atomic<int> callback_count_{0};
  std::vector<std::string> actions_;

 private:
  Mutex actions_lock_;

 private:
  FRIEND_TEST(INotifyTests, test_inotify_fire_event);
  FRIEND_TEST(INotifyTests, test_inotify_event_action);
  FRIEND_TEST(INotifyTests, test_inotify_optimization);
  FRIEND_TEST(INotifyTests, test_inotify_directory_watch);
  FRIEND_TEST(INotifyTests, DISABLED_test_inotify_recursion);
  FRIEND_TEST(INotifyTests, test_inotify_embedded_wildcards);
};

TEST_F(INotifyTests, test_inotify_run) {
  // Assume event type is registered.
  event_pub_ = std::make_shared<INotifyEventPublisher>(true);
  auto status = EventFactory::registerEventPublisher(event_pub_);
  EXPECT_TRUE(status.ok());

  // Create a temporary file to watch, open writeable
  FILE* fd = fopen(real_test_path.c_str(), "w");

  // Create a subscriber.
  auto sub = std::make_shared<TestINotifyEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Create a subscription context
  auto mc = std::make_shared<INotifySubscriptionContext>();
  mc->path = real_test_path;
  mc->mask = IN_ALL_EVENTS;
  status = EventFactory::addSubscription(
      "inotify", Subscription::create("TestINotifyEventSubscriber", mc));
  EXPECT_TRUE(status.ok());
  event_pub_->configure();

  // Create an event loop thread (similar to main)
  std::thread temp_thread(EventFactory::run, "inotify");
  EXPECT_TRUE(event_pub_->numEvents() == 0);

  // Cause an inotify event by writing to the watched path.
  fputs("inotify", fd);
  fclose(fd);

  // Wait for the thread's run loop to select.
  WaitForEvents(kMaxEventLatency);
  EXPECT_TRUE(event_pub_->numEvents() > 0);
  EventFactory::end();
  temp_thread.join();
}

TEST_F(INotifyTests, test_inotify_fire_event) {
  // Assume event type is registered.
  StartEventLoop();
  auto sub = std::make_shared<TestINotifyEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Create a subscriptioning context, note the added Event to the symbol
  auto sc = sub->GetSubscription(real_test_path, 0);
  sub->subscribe(&TestINotifyEventSubscriber::SimpleCallback, sc);
  event_pub_->configure();

  TriggerEvent(real_test_path);
  sub->WaitForEvents(kMaxEventLatency);

  // Make sure our expected event fired (aka subscription callback was called).
  EXPECT_TRUE(sub->count() > 0);
  StopEventLoop();
}

TEST_F(INotifyTests, test_inotify_event_action) {
  // Assume event type is registered.
  StartEventLoop();
  auto sub = std::make_shared<TestINotifyEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  auto sc = sub->GetSubscription(real_test_path, IN_ALL_EVENTS);
  sub->subscribe(&TestINotifyEventSubscriber::Callback, sc);
  event_pub_->configure();

  TriggerEvent(real_test_path);
  sub->WaitForEvents(kMaxEventLatency, 2);

  // Make sure the inotify action was expected.
  EXPECT_GT(sub->actions().size(), 0U);
  if (sub->actions().size() >= 2) {
    EXPECT_EQ(sub->actions()[0], "UPDATED");
  }

  StopEventLoop();
}

TEST_F(INotifyTests, test_inotify_optimization) {
  // Assume event type is registered.
  StartEventLoop();
  fs::create_directory(real_test_dir);

  // Adding a descriptor to a directory will monitor files within.
  SubscriptionAction(real_test_dir);
  EXPECT_TRUE(event_pub_->isPathMonitored(real_test_dir_path));

  // Adding a subscription to a file within a monitored directory is fine
  // but this will NOT cause an additional INotify watch.
  SubscriptionAction(real_test_dir_path);
  EXPECT_EQ(event_pub_->numDescriptors(), 1U);
  StopEventLoop();
}

TEST_F(INotifyTests, test_inotify_directory_watch) {
  StartEventLoop();

  auto sub = std::make_shared<TestINotifyEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  fs::create_directory(real_test_dir);
  fs::create_directory(real_test_sub_dir);

  // Subscribe to the directory inode
  auto mc = sub->createSubscriptionContext();
  mc->path = real_test_dir;
  mc->recursive = true;
  sub->subscribe(&TestINotifyEventSubscriber::Callback, mc);
  event_pub_->configure();

  // Trigger on a subdirectory's file.
  TriggerEvent(real_test_sub_dir_path);

  sub->WaitForEvents(kMaxEventLatency, 1);
  EXPECT_TRUE(sub->count() > 0);
  StopEventLoop();
}

TEST_F(INotifyTests, DISABLED_test_inotify_recursion) {
  // Create a non-registered publisher and subscriber.
  auto pub = std::make_shared<INotifyEventPublisher>(true);
  EventFactory::registerEventPublisher(pub);
  auto sub = std::make_shared<TestINotifyEventSubscriber>();

  // Create a mock directory structure.
  fs::create_directory(real_test_dir);

  // Create and test several subscriptions.
  auto sc = sub->createSubscriptionContext();

  sc->path = real_test_dir + "/*";
  sub->subscribe(&TestINotifyEventSubscriber::Callback, sc);
  // Trigger a configure step manually.
  pub->configure();

  // Expect a single monitor on the root of the fake tree.
  EXPECT_EQ(pub->path_descriptors_.size(), 1U);
  EXPECT_EQ(pub->path_descriptors_.count(real_test_dir + "/"), 1U);
  RemoveAll(pub);

  // Make sure monitors are empty.
  EXPECT_EQ(pub->numDescriptors(), 0U);

  auto sc2 = sub->createSubscriptionContext();
  sc2->path = real_test_dir + "/**";
  sub->subscribe(&TestINotifyEventSubscriber::Callback, sc2);
  pub->configure();

  // Expect only the directories to be monitored.
  // TODO test fails in the following assert.
  EXPECT_EQ(pub->path_descriptors_.size(), 11U);
  RemoveAll(pub);

  // Use a directory structure that includes a loop.
  boost::system::error_code ec;
  fs::create_symlink(real_test_dir, real_test_dir + "/link", ec);

  auto sc3 = sub->createSubscriptionContext();
  sc3->path = real_test_dir + "/**";
  sub->subscribe(&TestINotifyEventSubscriber::Callback, sc3);
  pub->configure();

  // Also expect canonicalized resolution (to prevent loops).
  EXPECT_EQ(pub->path_descriptors_.size(), 9U);
  RemoveAll(pub);

  EventFactory::deregisterEventPublisher("inotify");
}

TEST_F(INotifyTests, test_inotify_embedded_wildcards) {
  // Assume event type is not registered.
  event_pub_ = std::make_shared<INotifyEventPublisher>(true);
  EventFactory::registerEventPublisher(event_pub_);

  auto sub = std::make_shared<TestINotifyEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Create ./inotify-triggers/2/1/.
  fs::create_directories(real_test_dir + "/2/1");

  // Create a subscription to match an embedded wildcard: "*"
  // The assumption is a watch will be created on the 'most-specific' directory
  // before the wildcard request.
  auto mc = sub->createSubscriptionContext();
  mc->path = real_test_dir + "/*/1";
  mc->recursive = true;
  sub->subscribe(&TestINotifyEventSubscriber::Callback, mc);

  // Now the publisher must be configured.
  event_pub_->configure();

  // Assume there is one watched path: real_test_dir.
  ASSERT_EQ(event_pub_->numDescriptors(), 1U);
  EXPECT_EQ(event_pub_->path_descriptors_.count(real_test_dir + "/2/1/"), 1U);
}
}
