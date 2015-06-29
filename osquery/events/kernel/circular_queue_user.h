/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include "kernel/include/feeds.h"
#include <stdexcept>

namespace osquery {

class CQueueException : public std::runtime_error {
 public:
  explicit CQueueException(const char *str) : std::runtime_error(str) {};
};

class CQueue {
 public:
  /**
   * @brief Creates cqueue.
   *
   * This connects to the osquery kernel extension dev file and sets up a
   * shared buffer of the specified size.  The size must be accepted by the
   * kernel extension.
   *
   * @param size The size of the shared buffer used for communication.
   */
  CQueue(size_t size);

  /**
   * @brief Cleanup a cqueue.
   *
   * This closes the connection with dev port and frees up kernel resources.
   * Like the shared buffer.
   */
  ~CQueue();

  /**
   * @brief Sends a subscription call to the kernel extension.
   *
   * This sets up the event callbacks so we start hearing about the given event.
   *
   * @param event The event we are interested in.
   */
  void subscribe(osquery_event_t event);

  /**
   * @brief Dequeue's an event from the shared buffer.
   *
   * @param event (ouput) A pointer to the event dequeue if any.
   * @return Returns 0 if queue is empty, otherwise the number of the event put
   * into event.
   */
  osquery_event_t dequeue(void **event);

  /**
   * @brief Sync the cqueue structure with the cqueue structure in the kernel.
   *
   * This allow the two view of the buffer to maintain consistency.
   *
   * @param options Options to be passed to the kernel.  Primarily used for 
   *   OSQUERY_NO_BLOCK, which allows the sync to not block if there is no data.
   * @return Returns the number of dropped events, or negative if too many.
   */
  int kernelSync(int options);

 private:
  uint8_t *buffer_;
  size_t size_;
  uint8_t *max_read_;
  uint8_t *read_;
  int fd_;
};

}  // namespace osquery
