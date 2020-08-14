/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/ev2/simple_publisher.h>
#include <osquery/ev2/tests/utils.h>

#include <gtest/gtest.h>

namespace osquery {
namespace ev2 {
namespace {

class SimplePublisherTests : public testing::Test {};

class TestSubscription : public ev2::Subscription {
 public:
  explicit TestSubscription(const std::string& subscriber);
  ~TestSubscription() = default;

  std::size_t avail() const override {
    return 0;
  }

  std::size_t wait(std::size_t batch = 1,
                   std::chrono::milliseconds timeout =
                       std::chrono::milliseconds::zero()) override {
    return batch;
  }

  void abort() override {}
};

using TestPublisher = ev2::SimplePublisher<TestSubscription>;

TestSubscription::TestSubscription(const std::string& subscriber)
    : Subscription(subscriber, typeid(TestPublisher)) {}

TEST_F(SimplePublisherTests, test_subscribe) {
  TestPublisher pub("test");
  auto sub = std::make_shared<TestSubscription>("test");
  auto null_sub = std::make_shared<NullSubscription>("test");

  EXPECT_TRUE(pub.subscribe(sub));
  EXPECT_TRUE(pub.subscribe(sub));
  EXPECT_FALSE(pub.subscribe(null_sub));
}

} // namespace
} // namespace ev2
} // namespace osquery
