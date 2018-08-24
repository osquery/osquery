/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/ev2/event.h>
#include <osquery/ev2/subscription.h>

#include <mutex>
#include <queue>
#include <string>

namespace osquery {
namespace ev2 {

template <typename EventT>
class BufferedSubscription : public Subscription {
 public:
  explicit BufferedSubscription(
      const std::string& subscriber,
      const std::type_index& pub_type)
    : Subscription(subscriber, pub_type)
    , abort_(false)
    , waiting_(0)
  { }
  virtual ~BufferedSubscription() = default;

  unsigned int avail() const override
  {
    std::unique_lock<std::mutex> lock(mutex_);

    return buffer_.size();
  }

  unsigned int wait(
      unsigned int batch = 1,
      std::chrono::milliseconds timeout = std::chrono::milliseconds::zero()
      ) override {
    waiting_++;

    std::unique_lock<std::mutex> lock(mutex_);

    if (timeout == std::chrono::milliseconds::zero()) {
      cv_.wait(
          lock,
          [this, batch] { return buffer_.size() >= batch || abort_; }
          );
    } else {
      cv_.wait(
          lock,
          [this] { return !buffer_.empty() || abort_; }
          );
      cv_.wait_for(
          lock,
          timeout,
          [this, batch] { return buffer_.size() >= batch || abort_; }
          );
    }

    waiting_--;

    return buffer_.size();
  }

  void abort() override
  {
    abort_ = true;
    cv_.notify_all();

    while (waiting_ != 0) {
      /* spinlock */
    }

    abort_ = false;
  }

  EventT get()
  {
    std::unique_lock<std::mutex> lock(mutex_);

    EventT event = std::move(buffer_.front());
    buffer_.pop();

    return event;
  }

  void enqueue(EventT event)
  {
    std::unique_lock<std::mutex> lock(mutex_);

    buffer_.push(std::move(event));

    lock.unlock();
    cv_.notify_one();
  }

 private:
  std::queue<EventT> buffer_;

  bool abort_;

  mutable std::mutex mutex_;
  mutable std::condition_variable cv_;
  std::atomic<unsigned int> waiting_;
};

} // namespace ev2
} // namespace osquery
