/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
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
        abort_(false),
        waiting_(0) {}
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
   * @details This method is thread-safe as producer and consumer will probably
   * run on different threads, however it is not designed to handle
   * multiple simultaneous consumers. In case multiple threads call wait
   * simultaneously the implementation can only guarantee that
   * one of the pending threads will be released once the batch size is reached
   * however other threads might as well be released. The wait timeout will
   * always be respected. If you still want to use multiple consumer threads it
   * is up to you to decide how to handle the consumption of events. Remember
   * that take() shouldn't be called without guaranteeing first that there are
   * pending events by either calling wait() or avail().
   */
  std::size_t wait(std::size_t batch = 1,
                   std::chrono::milliseconds timeout =
                       std::chrono::milliseconds::zero()) override {
    waiting_++;

    std::unique_lock<std::mutex> lock(buffer_mutex_);

    if (timeout == std::chrono::milliseconds::zero()) {
      buffer_cv_.wait(
          lock, [this, batch] { return buffer_.size() >= batch || abort_; });
    } else {
      buffer_cv_.wait_for(lock, timeout, [this, batch] {
        return buffer_.size() >= batch || abort_;
      });
    }

    waiting_--;

    return buffer_.size();
  }

  /**
   * @brief See ev2::Subscription::abort()
   *
   * @details Calling abort() will block until all threads blocked on wait()
   * exit. Calling abort() will leave the object in a working state and it is
   * safe to call to call any method on the object as soon as abort() exits. No
   * events will be lost in by calling abort().
   */
  void abort() override {
    abort_ = true;
    buffer_cv_.notify_all();

    while (waiting_ != 0) {
      /* spinlock */
    }

    abort_ = false;
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

  std::atomic<std::size_t> waiting_;

  bool abort_;
};

} // namespace ev2
} // namespace osquery
