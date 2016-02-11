/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <atomic>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include <osquery/core.h>

// osquery is built with various versions of thrift that use different search
// paths for their includes. Unfortunately, changing include paths is not
// possible in every build system.
// clang-format off
#ifndef OSQUERY_THRIFT_LIB
#define OSQUERY_THRIFT_LIB thrift
#endif

#ifndef OSQUERY_THRIFT_SERVER_LIB
#define OSQUERY_THRIFT_SERVER_LIB thrift/server
#endif

#ifndef OSQUERY_THRIFT_POINTER
#define OSQUERY_THRIFT_POINTER boost
#endif

#include CONCAT(OSQUERY_THRIFT_LIB,/concurrency/Thread.h)
#include CONCAT(OSQUERY_THRIFT_LIB,/concurrency/ThreadManager.h)
#include CONCAT(OSQUERY_THRIFT_LIB,/concurrency/PosixThreadFactory.h)
// clang-format on

namespace osquery {

using namespace apache::thrift::concurrency;

/// Create easier to reference typedefs for Thrift layer implementations.
#define SHARED_PTR_IMPL OSQUERY_THRIFT_POINTER::shared_ptr
using InternalThreadManager = apache::thrift::concurrency::ThreadManager;
using InternalThreadManagerRef = SHARED_PTR_IMPL<InternalThreadManager>;

/**
 * @brief Default number of threads in the thread pool.
 *
 * The amount of threads that the thread pool will be created with if another
 * value is not specified on the command-line.
 */
extern const int kDefaultThreadPoolSize;

class InternalRunnable : public Runnable {
 public:
  InternalRunnable() : run_(false) {}
  virtual ~InternalRunnable() {}

 public:
  /// The boost::thread entrypoint.
  void run() {
    run_ = true;
    start();
  }

  /// Check if the thread's entrypoint (run) executed, meaning thread context
  /// was allocated.
  bool hasRun() { return run_; }

  /// The runnable may also tear down services before the thread context
  /// is removed.
  virtual void stop() {}

 protected:
  /// Require the runnable thread define an entrypoint.
  virtual void start() = 0;

 private:
  std::atomic<bool> run_{false};
};

/// An internal runnable used throughout osquery as dispatcher services.
using InternalRunnableRef = std::shared_ptr<InternalRunnable>;
using InternalThreadRef = std::shared_ptr<boost::thread>;
/// A thrift internal runnable with variable pointer wrapping.
using ThriftInternalRunnableRef = SHARED_PTR_IMPL<InternalRunnable>;
using ThriftThreadFactory = SHARED_PTR_IMPL<PosixThreadFactory>;

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
  static Dispatcher& instance() {
    static Dispatcher instance;
    return instance;
  }

  /**
   * @brief Add a task to the dispatcher.
   *
   * Adding tasks to the Dispatcher's thread pool requires you to create a
   * "runnable" class which publicly implements Apache Thrift's Runnable
   * class. Create a shared pointer to the class and you're all set to
   * schedule work.
   *
   * @code{.cpp}
   *   class TestRunnable : public apache::thrift::concurrency::Runnable {
   *    public:
   *     int* i;
   *     TestRunnable(int* i) : i(i) {}
   *     virtual void run() { ++*i; }
   *   };
   *
   *   int i = 5;
   *   Dispatcher::add(std::make_shared<TestRunnable>(&i);
   *   while (dispatch->totalTaskCount() > 0) {}
   *   assert(i == 6);
   * @endcode
   *
   * @param task a C++11 std shared pointer to an instance of a class which
   * publicly inherits from `apache::thrift::concurrency::Runnable`.
   *
   * @return osquery success status
   */
  static Status add(ThriftInternalRunnableRef task);

  /// See `add`, but services are not limited to a thread poll size.
  static Status addService(InternalRunnableRef service);

  /**
   * @brief Getter for the underlying thread manager instance.
   *
   * Use this getter if you'd like to perform some operations which the
   * Dispatcher API doesn't support, but you are certain are supported by the
   * backing Apache Thrift thread manager.
   *
   * Use this method with caution, as it only exists to allow developers to
   * iterate quickly in the event that the pragmatic decision to access the
   * underlying thread manager has been determined to be necessary.
   *
   * @code{.cpp}
   *   auto t = osquery::Dispatcher::getThreadManager();
   * @endcode
   *
   * @return a shared pointer to the Apache Thrift `ThreadManager` instance
   * which is currently being used to orchestrate multi-threaded operations.
   */
  InternalThreadManagerRef getThreadManager() const;

  /**
   * @brief Joins the thread manager.
   *
   * This is the same as stop, except that it will block until all the workers
   * have finished their work. At that point the ThreadManager will transition
   * into the STOPPED state.
   */
  static void join();

  /// See `join`, but applied to osquery services.
  static void joinServices();

  /// Destroy and stop all osquery service threads and service objects.
  static void stopServices();

  /**
   * @brief Get the current state of the thread manager.
   *
   * @return an Apache Thrift STATE enum.
   */
  InternalThreadManager::STATE state() const;

  /**
   * @brief Add a worker thread.
   *
   * Use this method to add an additional thread to the thread pool.
   *
   * @param value is a size_t indicating how many additional worker threads
   * should be added to the thread group. If not parameter is supplied, one
   * worker thread is added.
   *
   * @see osquery::Dispatcher::removeWorker
   */
  static void addWorker(size_t value = 1);

  /**
   * @brief Remove a worker thread.
   *
   * Use this method to remove a thread from the thread pool.
   *
   * @param value is a size_t indicating how many additional worker threads
   * should be removed from the thread group. If not parameter is supplied,
   * one worker thread is removed.
   *
   * @see osquery::Dispatcher::addWorker
   */
  static void removeWorker(size_t value = 1);

  /**
   * @brief Gets the current number of idle worker threads.
   *
   * @return the number of idle worker threads.
   */
  size_t idleWorkerCount() const;

  /**
   * @brief Gets the current number of total worker threads.
   *
   * @return the current number of total worker threads.
   */
  size_t workerCount() const;

  /**
   * @brief Gets the current number of pending tasks.
   *
   * @return the current number of pending tasks.
   */
  size_t pendingTaskCount() const;

  /**
   * @brief Gets the current number of pending and executing tasks.
   *
   * @return the current number of pending and executing tasks.
   */
  size_t totalTaskCount() const;

  /**
   * @brief Gets the maximum pending task count. 0 indicates no maximum.
   *
   * @return the maximum pending task count. 0 indicates no maximum.
   */
  size_t pendingTaskCountMax() const;

  /**
   * @brief Gets the number of tasks which have been expired without being
   * run.
   *
   * @return he number of tasks which have been expired without being run.
   */
  size_t expiredTaskCount() const;

 private:
  /**
   * @brief Default constructor.
   *
   * Since instances of Dispatcher should only be created via instance(),
   * Dispatcher's constructor is private.
   */
  Dispatcher() {}
  Dispatcher(Dispatcher const&);
  void operator=(Dispatcher const&);
  virtual ~Dispatcher();

  /// Initialize the thread poll when the first dispatcher thread is needed.
  void init();

 private:
  /**
   * @brief Internal shared pointer which references Thrift's thread manager
   *
   * All thread operations occur via Apache Thrift's ThreadManager class. This
   * private member represents a shared pointer to an instantiation of that
   * thread manager, which can be used to accomplish various threading
   * objectives.
   *
   * @see getThreadManager
   */
  InternalThreadManagerRef thread_manager_{nullptr};

  /// The set of shared osquery service threads.
  std::vector<InternalThreadRef> service_threads_;

  /// The set of shared osquery services.
  std::vector<InternalRunnableRef> services_;

 private:
  friend class ExtensionsTest;
};

/// Allow a dispatched thread to wait while processing or to prevent thrashing.
void interruptableSleep(size_t milli);
}
