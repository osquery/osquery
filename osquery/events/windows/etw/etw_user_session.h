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
#include <osquery/events/windows/etw/etw_krabs.h>

namespace osquery {

class Status;
class EtwProviderConfig;

/**
 * @brief Manages the trace session created to listen
 * for ETW user space events. This class uses a thread astraction provided by
 * Osquery InternalRunnable class to handle the ETW trace session on a dedicated
 * thread.
 */
class UserEtwSessionRunnable final : public InternalRunnable {
  using EtwUserProvider = std::shared_ptr<krabs::user_trace>;
  using UserProviderRef = std::shared_ptr<krabs::provider<>>;
  using UserProvidersCollection = std::vector<UserProviderRef>;

 public:
  UserEtwSessionRunnable(const std::string& runnableName);
  virtual ~UserEtwSessionRunnable();

  /**
   * @brief Adds a new provider to the list of kernel space providers to
   * listen. It also registers the preprocesor and postprocessor callbacks to
   * handle incoming ETW events.
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
   * @brief Pause the ongoing events listening operation
   */
  virtual void pause();

  /**
   * @brief Resume the ongoing events listening operation
   */
  virtual void resume();

  /**
   * @brief Best effort user trace initialization helper
   */
  void initUserTraceSession(const std::string& sessionName);

  /**
   * @brief Best effort user trace stop helper
   */
  void stopUserTraceSession(const std::string& sessionName);

  /**
   * @brief User trace session object provided by KrabsETW library
   */
  std::shared_ptr<krabs::user_trace> userTraceSession_{nullptr};

  /**
   * @brief Running Userspace Providers cache
   */
  UserProvidersCollection runningProviders_;

  /**
   * @brief Mutex to keep the class thread safe
   */
  mutable std::mutex mutex_;

  /**
   * @brief Flag to signal when event processing should be stopped
   */
  std::atomic<bool> endTraceSession_{false};

  /**
   * @brief Flag to signal when trace session is stopped
   */
  std::atomic<bool> traceSessionStopped_{false};

  /**
   * @brief Condition variable to signal trace session is ready to resume
   */
  std::condition_variable condition_;
};

} // namespace osquery
