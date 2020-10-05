/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>

#include <osquery/ev2/publisher.h>
#include <osquery/ev2/subscription.h>

namespace osquery {
namespace ev2 {

class TestEvent {
 public:
  using Id = uint64_t;
  using Time = std::chrono::system_clock::time_point;

  explicit TestEvent(Id id, Time time);
  virtual ~TestEvent() = default;

  bool operator==(const TestEvent& rhs) const;
  bool operator!=(const TestEvent& rhs) const;

  const Id id;
  const Time time;
};

class NullPublisher : public ev2::Publisher {
 public:
  explicit NullPublisher(const std::string& name);
  ~NullPublisher() = default;

  ExpectedSuccess<Publisher::Error> subscribe(
      std::shared_ptr<Subscription> subscription) override;
};

class NullSubscription : public ev2::Subscription {
 public:
  explicit NullSubscription(const std::string& subscriber);
  ~NullSubscription() = default;

  std::size_t avail() const override;
  std::size_t wait(std::size_t batch = 1,
                   std::chrono::milliseconds timeout =
                       std::chrono::milliseconds::zero()) override;
  void abort() override;
};

} // namespace ev2
} // namespace osquery
