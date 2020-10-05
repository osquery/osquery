/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>

#include <gtest/gtest.h>

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/utils/status/status.h>

namespace osquery {

class DispatcherTests : public testing::Test {
  void TearDown() override {
    Dispatcher::instance().resetStopping();
  }
};

TEST_F(DispatcherTests, test_singleton) {
  auto& one = Dispatcher::instance();
  auto& two = Dispatcher::instance();
  EXPECT_EQ(&one, &two);
}

class InternalTestableRunnable : public InternalRunnable {
 public:
  InternalTestableRunnable(const std::string& name) : InternalRunnable(name) {}

  bool interrupted() override {
    // A small conditional to force-skip an interruption check, used in testing.
    if (!checked_) {
      checked_ = true;
      return false;
    } else {
      return InternalRunnable::interrupted();
    }
  }

 private:
  /// Testing only, track the interruptible check for interruption.
  bool checked_{false};
};

class TestRunnable : public InternalTestableRunnable {
 public:
  explicit TestRunnable() : InternalTestableRunnable("TestRunnable") {}

  virtual void start() override {
    ++i;
  }

  void reset() {
    i = 0;
  }

  size_t count() {
    return i;
  }

 private:
  static std::atomic<size_t> i;
};

std::atomic<size_t> TestRunnable::i{0};

TEST_F(DispatcherTests, test_service_count) {
  auto runnable = std::make_shared<TestRunnable>();

  auto service_count = Dispatcher::instance().serviceCount();
  // The service exits after incrementing.
  auto s = Dispatcher::addService(runnable);
  EXPECT_TRUE(s);

  // Wait for the service to stop.
  Dispatcher::joinServices();

  // Make sure the service is removed.
  EXPECT_EQ(service_count, Dispatcher::instance().serviceCount());
}

TEST_F(DispatcherTests, test_run) {
  auto runnable = std::make_shared<TestRunnable>();
  runnable->reset();

  // The service exits after incrementing.
  Dispatcher::addService(runnable);
  Dispatcher::joinServices();
  EXPECT_EQ(1U, runnable->count());
  EXPECT_TRUE(runnable->hasRun());

  // This runnable cannot be executed again.
  auto s = Dispatcher::addService(runnable);
  EXPECT_FALSE(s);

  Dispatcher::joinServices();
  EXPECT_EQ(1U, runnable->count());
}

TEST_F(DispatcherTests, test_independent_run) {
  // Nothing stops two instances of the same service from running.
  auto r1 = std::make_shared<TestRunnable>();
  auto r2 = std::make_shared<TestRunnable>();
  r1->reset();

  Dispatcher::addService(r1);
  Dispatcher::addService(r2);
  Dispatcher::joinServices();

  EXPECT_EQ(2U, r1->count());
}

class BlockingTestRunnable : public InternalTestableRunnable {
 public:
  explicit BlockingTestRunnable()
      : InternalTestableRunnable("BlockingTestRunnable") {}

  virtual void start() override {
    // Wow that's a long sleep!
    pause(std::chrono::seconds(100));
  }
};

TEST_F(DispatcherTests, test_interruption) {
  auto r1 = std::make_shared<BlockingTestRunnable>();
  Dispatcher::addService(r1);

  // This service would normally wait for 100 seconds.
  r1->interrupt();

  Dispatcher::joinServices();
  EXPECT_TRUE(r1->hasRun());
}

TEST_F(DispatcherTests, test_stop_dispatcher) {
  Dispatcher::stopServices();

  auto r1 = std::make_shared<TestRunnable>();
  auto s = Dispatcher::addService(r1);
  EXPECT_FALSE(s);
}
}
