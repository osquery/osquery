/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest_prod.h>

#include <boost/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/utils/mutex.h>

namespace osquery {

class Status;
class Dispatcher;

class InterruptibleRunnable {
 public:
  virtual ~InterruptibleRunnable() = default;

  /**
   * @brief The std::thread's interruption point.
   */
  virtual void interrupt() final;

  /// Returns the runner name
  std::string name() const {
    return runnable_name_;
  }

 protected:
  /// Allow the runnable to check interruption.
  virtual bool interrupted();

  /// Require the runnable thread to define a stop/interrupt point.
  virtual void stop() = 0;

  /// Put the runnable into an interruptible sleep.
  void pause(std::chrono::milliseconds milli);

  /// Name of the InterruptibleRunnable which is also the thread name
  std::string runnable_name_;

 private:
  /**
   * @brief Used to wait for the interruption notification while sleeping
   */
  std::mutex condition_lock;

  /// If a service includes a run loop it should check for interrupted.
  std::atomic<bool> interrupted_{false};

  /// Wait for notification or a pause expiration.
  std::condition_variable condition_;

 private:
  FRIEND_TEST(DispatcherTests, test_run);
  FRIEND_TEST(DispatcherTests, test_independent_run);
  FRIEND_TEST(DispatcherTests, test_interruption);
  FRIEND_TEST(BufferedLogForwarderTests, test_async);
};

class InternalRunnable : private boost::noncopyable,
                         public InterruptibleRunnable {
 public:
  InternalRunnable(const std::string& name) : run_(false) {
    runnable_name_ = name;
  }
  virtual ~InternalRunnable() override = default;

 public:
  /**
   * @brief The std::thread entrypoint.
   *
   * This is used by the Dispatcher only.
   */
  virtual void run() final;

  /**
   * @brief Check if the thread's entrypoint (run) executed.
   *
   * It is possible for the Runnable to be allocated without the thread context.
   * #hasRun makes a much better guess at the state of the thread.
   * If it has run then stop must be called.
   */
  bool hasRun() {
    return run_;
  }

 protected:
  /// Require the runnable thread define an entrypoint.
  virtual void start() = 0;

  /// The runnable thread may optionally define a stop/interrupt point.
  void stop() override {}

 private:
  std::atomic<bool> run_{false};
};

/// An internal runnable used throughout osquery as dispatcher services.
using InternalRunnableRef = std::shared_ptr<InternalRunnable>;
using InternalThreadRef = std::unique_ptr<std::thread>;

/**
 * @brief Singleton for queuing asynchronous tasks to be executed in parallel
 *
 * Dispatcher is a singleton which can be used to coordinate the parallel
 * execution of asynchronous tasks across an application. Internally,
 * Dispatcher is back by the Apache Thrift thread pool.
 */
class Dispatcher : private boost::noncopyable {
 public:
  /**
   * @brief The primary way to access the Dispatcher factory facility.
   *
   * @code{.cpp} auto dispatch = osquery::Dispatcher::instance(); @endcode
   *
   * @return The osquery::Dispatcher instance.
   */
  static Dispatcher& instance();

  /// See `add`, but services are not limited to a thread poll size.
  static Status addService(InternalRunnableRef service);

  /// See `join`, but applied to osquery services.
  static void joinServices();

  /// Destroy and stop all osquery service threads and service objects.
  static void stopServices();

  /// Return number of services.
  size_t serviceCount() const;

 private:
  /**
   * @brief Default constructor.
   *
   * Since instances of Dispatcher should only be created via instance(),
   * Dispatcher's constructor is private.
   */
  Dispatcher() = default;

 private:
  /// When a service ends, it will remove itself from the dispatcher.
  static void removeService(const InternalRunnable* service);

 public:
  /// For testing only, reset the stopping status for unittests.
  void resetStopping();

 private:
  /// The set of shared osquery service threads.
  std::vector<InternalThreadRef> service_threads_;

  /// The set of shared osquery services.
  std::vector<InternalRunnableRef> services_;

  // Protection around service access.
  mutable Mutex mutex_;

  /**
   * @brief Signal to the Dispatcher that no services should be created.
   *
   * The Dispatcher will not add services if it is shutting down until
   * a join has completed of existing services.
   *
   * This prevents a very strange race where the dispatcher is signaled to
   * abort or interrupt and serviced are sill waiting to be added.
   * A future join will be requested AFTER all services were expected to have
   * been interrupted.
   */
  bool stopping_{false};

 private:
  friend class InternalRunnable;

  // Tests
  friend class ConfigTests;
  friend class DispatcherTests;
  friend class ExtensionsTest;
};
} // namespace osquery
