/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <stdexcept>
#include <string>

#include <boost/noncopyable.hpp>

#include "kernel/include/feeds.h"

namespace osquery {

class CQueueException : public std::runtime_error {
 public:
  explicit CQueueException(const std::string &s) : std::runtime_error(s){};
};

class CQueue : private boost::noncopyable {
 public:
  /**
   * @brief Structure to hold event metadata and pointer to an event.
   */
  struct event {
    size_t size;
    osquery_event_time_t time;

    // The flexible data must remain as the last member.
    char buf[];
  };

  /**
   * @brief Creates cqueue.
   *
   * This connects to the osquery kernel extension dev file and sets up a
   * shared buffer of the specified size.  The size must be accepted by the
   * kernel extension.
   *
   * @param device The device node path for ioctl communication.
   * @param size The size of the shared buffer used for communication.
   */
  explicit CQueue(const std::string &device, size_t size);

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
   * @param event (output) A pointer to the event dequeue if any.
   * @return Returns 0 if queue is empty, otherwise the number of the event put
   * into event.
   */
  osquery_event_t dequeue(event **event);

  /**
   * @brief Sync the cqueue structure with the cqueue structure in the kernel.
   *
   * This allow the two view of the buffer to maintain consistency.
   *
   * @param options Options to be passed to the kernel. Primarily used for
   *   OSQUERY_OPTIONS_NO_BLOCK, which allows the sync to not block if there is
   *   no data.
   * @return Returns the number of dropped events, or negative if too many.
   */
  int kernelSync(int options);

 private:
  uint8_t *buffer_{nullptr};
  size_t size_{0};
  uint8_t *max_read_{nullptr};
  uint8_t *read_{nullptr};
  int fd_{-1};
};

} // namespace osquery
