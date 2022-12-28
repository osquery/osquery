/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/windows/etw/etw_concurrent_queue.h>
#include <osquery/events/windows/etw/etw_provider_config.h>

namespace osquery {

class Status;

/**
 * @brief Manages the collection of post-processing
 * callbacks in-charge of processing and dispatching events to event
 * subscribers.
 */
class EtwPostProcessorsRunnable final : public InternalRunnable {
 public:
  EtwPostProcessorsRunnable(const std::string& runnableName,
                            ConcurrentEventQueueRef& sharedQueue);
  virtual ~EtwPostProcessorsRunnable();

  /**
   * @brief Registers a post-processor callback handler to a list of etw
   * event types to handle.
   */
  Status addProvider(const EtwProviderConfig& configData);

 protected:
  /**
   * @brief Start the thread managed by InternalRunnable class
   */
  virtual void start() override;

  /**
   * @brief Stop the thread managed by InternalRunnable class
   */
  virtual void stop() override;

 private:
  /**
   * @brief Event enrichment to every ETW event is performed here
   */
  bool CommonPostProcessing(EtwEventDataRef& data);

  using ProviderProcessors =
      std::map<EtwEventType, EtwProviderConfig::EventProviderPostProcessor>;

  /**
   * @brief Collection of post-processing callbacks
   */
  ProviderProcessors etwPostProcessors_;

  /**
   * @brief Atomic flag to determine if thread should keep running
   */
  std::atomic<bool> shouldRun_{true};

  /**
   * @brief Concurrent event queue reference
   */
  ConcurrentEventQueueRef& concurrentQueue_;
};

} // namespace osquery
