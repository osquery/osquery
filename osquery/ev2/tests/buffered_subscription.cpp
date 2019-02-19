/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/ev2/buffered_subscription.h>
#include <osquery/ev2/simple_publisher.h>
#include <osquery/ev2/tests/utils.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <thread>

namespace osquery {
namespace ev2 {
namespace {

class BufferedSubscriptionTests : public testing::Test {};

class TestSubscription : public ev2::BufferedSubscription<TestEvent> {
 public:
  explicit TestSubscription(const std::string& subscriber)
      : BufferedSubscription(subscriber, typeid(nullptr)) {}
};

TEST_F(BufferedSubscriptionTests, test_enqueue_take) {
  TestSubscription sub("test");
  TestEvent ev_in(0xdeadbeef, std::chrono::system_clock::now());

  EXPECT_EQ(sub.avail(), 0);

  sub.enqueue(ev_in);

  EXPECT_EQ(sub.avail(), 1);

  TestEvent ev_out = sub.take();

  EXPECT_EQ(sub.avail(), 0);
  EXPECT_EQ(ev_in, ev_out);
}

TEST_F(BufferedSubscriptionTests, test_wait_no_timeout) {
  TestSubscription sub("test");
  TestEvent ev(0xdeadbeef, std::chrono::system_clock::now());

  auto call_wait = [&sub]() {
    sub.wait();

    EXPECT_EQ(sub.avail(), 1);
  };

  EXPECT_EQ(sub.avail(), 0);

  std::thread thread(call_wait);

  sub.enqueue(ev);

  thread.join();
}

TEST_F(BufferedSubscriptionTests, test_wait_timeout) {
  TestSubscription sub("test");

  auto call_wait = [&sub]() {
    sub.wait(1, std::chrono::milliseconds(1));

    EXPECT_EQ(sub.avail(), 0);
  };

  EXPECT_EQ(sub.avail(), 0);

  std::thread thread(call_wait);

  thread.join();
}

TEST_F(BufferedSubscriptionTests, test_batch) {
  const std::size_t test_batch_size = 10;
  std::vector<TestEvent> events;

  TestSubscription sub("test");

  auto call_wait = [&sub, test_batch_size]() {
    sub.wait(test_batch_size);

    EXPECT_EQ(sub.avail(), test_batch_size);
  };

  EXPECT_EQ(sub.avail(), 0);

  std::thread thread(call_wait);

  for (std::size_t i = 0; i < test_batch_size; i++) {
    events.emplace_back(i, std::chrono::system_clock::now());
    sub.enqueue(events.front());
    EXPECT_EQ(sub.avail(), i + 1);
  }

  thread.join();
}

} // namespace
} // namespace ev2
} // namespace osquery
