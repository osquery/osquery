/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/noncopyable.hpp>

#include <osquery/events/windows/etw/etw_concurrent_queue.h>

namespace osquery {

class EtwProviderConfig;
class UserEtwSessionRunnable;
class KernelEtwSessionRunnable;
class EtwPostProcessorsRunnable;
class Status;

/**
 * @brief EtwController manages the running ETW sessions and the events
 * processing logic. This class abstracts the caller from the low-level ETW API
 * details by exposing a clean and session-agnostic way to subscribe to new
 * event optics.
 */
class EtwController : public boost::noncopyable {
 public:
  /**
   * @brief Ensures that EtwController class only has one instance, and
   * it provides a global point of access to it.
   *
   * @return Reference to the single global EtwController instance
   */
  static EtwController& instance();

  /**
   * @brief Uses a given ETWProviderConfig data object to determine which
   * ETW provider should be listened. It also registers the pre-processor and
   * post-processor user-defined ETW callbacks that will be used during event
   * processing.
   *
   * @param configData ETW Provider configuration
   *
   * @return Status of the provider listening and processing request
   */
  Status addProvider(const EtwProviderConfig& configData);

  /**
   * @brief Dispatches events captured by preprocessor callbacks into the
   * processing pipeline logic.
   */
  void dispatchETWEvents(const EtwEventDataRef& data);

 private:
  const std::string runNameUserETWSession = "OsqueryUserETWSession";
  const std::string runNameKernelETWSession = "OsqueryKernelETWSession";
  const std::string runNamePostProcessingEngine = "EtwPostProcessingEngine";

  EtwController() = default;
  virtual ~EtwController() = default;

  /**
   * @brief Starts the event listening and event processing pipeline. This
   * also manages the ETW sessions for userspace and kernel ETW providers.
   *
   * @return Status of the ETW listening operations
   */
  Status startProcessing();

  /**
   * @brief ETW engine initialization logic. ETW sessions and post-processing
   * pipeline is initialized here.
   */
  Status initialize();
  bool isInitialized() const;

  std::atomic<bool> initialized_{false};
  std::shared_ptr<UserEtwSessionRunnable> etwUserSession_{nullptr};
  std::shared_ptr<KernelEtwSessionRunnable> etwKernelSession_{nullptr};
  std::shared_ptr<EtwPostProcessorsRunnable> etwPostProcessingEngine_{nullptr};
  std::shared_ptr<ConcurrentEventQueue> concurrentQueue_{nullptr};
  mutable std::mutex mutex_;
};

} // namespace osquery
