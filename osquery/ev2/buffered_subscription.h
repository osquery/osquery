/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/ev2/subscription.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <queue>
#include <string>

namespace osquery {
namespace ev2 {

/**
 * @brief Simple queue based ev2::Subscription.
 *
 * @details Provides a basic queue based ev2::Subscription buffering events for
 * the subscriber.
 */
template <typename EventT>
class BufferedSubscription : public Subscription {
 public:
  /**
   * @brief BufferedSubscription constructor.
   *
   * @params subscriber See ev2::Subscription::Subscription()
   * @params pub_type See ev2::Subscription::Subscription()
   */
  explicit BufferedSubscription(std::string subscriber,
                                std::type_index pub_type)
      : Subscription(std::move(subscriber), std::move(pub_type)),
        abort_(false) {}
  virtual ~BufferedSubscription() = default;

  /**
   * @brief See ev2::Subscription::avail().
   *
   * @details Returns the current total number of events buffered. As expected
   * the value returned by this method increases after calling enqueue() and
   * decreases after calling take() and won't be change otherwise.
   */
  std::size_t avail() const override {
    std::unique_lock<std::mutex> lock(buffer_mutex_);

    return buffer_.size();
  }

  /**
   * @brief See ev2::Subscription::wait().
   *
   * @details Block until at least batch events are available or timeout is
   * reached (for timeout != 0). Basically a blocking version of avail(). This
   * method is thread-safe but does not support concurrent calls. When called
   * concurrently the behaviour is undefined.
   */
  std::size_t wait(std::size_t batch = 1,
                   std::chrono::milliseconds timeout =
                       std::chrono::milliseconds::zero()) override {
    std::unique_lock<std::mutex> lock(buffer_mutex_);

    waiting_ = true;

    if (timeout == std::chrono::milliseconds::zero()) {
      buffer_cv_.wait(
          lock, [this, batch] { return buffer_.size() >= batch || abort_; });
    } else {
      buffer_cv_.wait_for(lock, timeout, [this, batch] {
        return buffer_.size() >= batch || abort_;
      });
    }

    abort_ = false;
    waiting_ = false;

    return buffer_.size();
  }

  /**
   * @brief See ev2::Subscription::abort()
   *
   * @details Notify thread blocked on wait() to exit. It is safe to call this
   * method when even when no thread is blocked on wait(), in which case this
   * will be a no-op. Calling abort() will leave the object in a working state
   * and it is safe to keep using the object. This will also not discard any
   * events.
   */
  void abort() override {
    std::unique_lock<std::mutex> lock(buffer_mutex_);

    if (waiting_) {
      abort_ = true;
      buffer_cv_.notify_one();
    }
  }

  /**
   * @brief Retrieve one event from the buffer. Before calling take it is up to
   * the user to guarantee the buffer contains elements by calling avail() or
   * wait(). Calling take() on an empty container will lead to undefined
   * behaviour.
   *
   * @returns The event at the top of the queue.
   */
  EventT take() {
    std::unique_lock<std::mutex> lock(buffer_mutex_);

    EventT event = std::move(buffer_.front());
    buffer_.pop();

    return event;
  }

  /**
   * @brief Enqueue one event on the buffer.
   */
  void enqueue(EventT event) {
    std::unique_lock<std::mutex> lock(buffer_mutex_);

    buffer_.push(std::move(event));

    lock.unlock();
    buffer_cv_.notify_all();
  }

 private:
  std::queue<EventT> buffer_;
  mutable std::mutex buffer_mutex_;
  mutable std::condition_variable buffer_cv_;

  bool abort_;
  bool waiting_;
};

} // namespace ev2
} // namespace osquery
