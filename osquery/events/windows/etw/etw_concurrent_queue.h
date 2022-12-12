/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>

#include <boost/noncopyable.hpp>

#include <osquery/events/windows/etw/etw_data_event.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

/**
 * @brief Thread-safe Concurrent Queue
 */
template <typename T>
class ConcurrentQueue : public boost::noncopyable {
 public:
  ConcurrentQueue() = default;

  ConcurrentQueue(ConcurrentQueue<T>&& other) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_ = std::move(other.queue_);
  }

  /**
   * @brief Returns the current size of the queue.
   */
  unsigned long size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<unsigned long>(queue_.size());
  }

  /**
   * @brief Checks if the queue is empty
   */
  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

  /**
   * @brief Removes the front element from the queue. This call will block
   * and return only when an element is successfully obtained from the queue.
   * The returned element will be removed from the queue.
   */
  T pop() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [&] { return !queue_.empty(); });
    T data = queue_.front();
    queue_.pop();
    return data;
  }

  /**
   * @brief Stores a new element to the back of the queue
   */
  void push(const T& item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(item);
    condition_.notify_one();
  }

 private:
  std::queue<T> queue_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
};

/**
 * @brief Concurrent Queue for ETW events
 */
using ConcurrentEventQueue = ConcurrentQueue<EtwEventDataRef>;
using ConcurrentEventQueueRef = std::shared_ptr<ConcurrentEventQueue>;

} // namespace osquery