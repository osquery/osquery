// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <vector>

#ifdef FBOSQUERY
#include <thrift/lib/cpp/concurrency/Thread.h>
#include <thrift/lib/cpp/concurrency/PosixThreadFactory.h>
#include <thrift/lib/cpp/concurrency/ThreadManager.h>
#else
#include <thrift/concurrency/Thread.h>
#include <thrift/concurrency/PosixThreadFactory.h>
#include <thrift/concurrency/ThreadManager.h>
#endif

#include <osquery/status.h>

namespace osquery {

/**
 * @brief Default number of threads in the thread pool.
 *
 * The amount of threads that the thread pool will be created with if another
 * value is not specified on the command-line.
 */
extern const int kDefaultThreadPoolSize;

/**
 * @brief Singleton for queueing asynchronous tasks to be executed in parallel
 *
 * Dispatcher is a singleton which can be used to coordinate the parallel
 * execution of asynchronous tasks across an application. Internally,
 * Dispatcher is back by the Apache Thrift thread pool.
 */
class Dispatcher {
 public:
  /**
   * @brief The primary way to access the Dispatcher singleton.
   *
   * osquery::Dispatcher::getInstance() provides access to the Dispatcher
   * singleton.
   *
   * @code{.cpp} auto dispatch = osquery::Dispatcher::getInstance(); @endcode
   *
   * @return a shared pointer to an instance of osquery::Dispatch.
   */
  static Dispatcher& getInstance();

  /**
   * @brief add a task to the dispatcher.
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
   *   auto dispatch = osquery::Dispatcher::getInstance(); int i = 5;
   *   dispatch->add(std::make_shared<TestRunnable>(&i);
   *   while (dispatch->totalTaskCount() > 0) {}
   *   assert(i == 6);
   * @endcode
   *
   * @param task a C++11 std shared pointer to an instance of a class which
   * publicly inherits from `apache::thrift::concurrency::Runnable`.
   *
   * @return an instance of osquery::Status, indicating the success or failure
   * of the operation.
   */
  Status add(std::shared_ptr<apache::thrift::concurrency::Runnable> task);

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
   *   auto t = osquery::Dispatcher::getInstance()->getThreadManager();
   * @endcode
   *
   * @return a shared pointer to the Apache Thrift `ThreadManager` instance
   * which is currently being used to orchestrate multi-threaded operations.
   */
  std::shared_ptr<apache::thrift::concurrency::ThreadManager>
  getThreadManager();

  /**
   * @brief Joins the thread manager.
   *
   * This is the same as stop, except that it will block until all the workers
   * have finished their work. At that point the ThreadManager will transition
   * into the STOPPED state.
   */
  void join();

  /**
   * @brief Get the current state of the thread manager.
   *
   * @return an Apache Thrift STATE enum.
   */
  apache::thrift::concurrency::ThreadManager::STATE state() const;

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
  void addWorker(size_t value = 1);

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
  void removeWorker(size_t value = 1);

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
   * Since instances of Dispatcher should only be created via getInstance(),
   * Dispatcher's constructor is private.
   */
  Dispatcher();

 private:
  /**
   * @brief Internal shared pointer which references Thrift's thread manager
   *
   * All thread operations occur via Apache Thrift's ThreadManager class. This
   * private member represents a shared pointer to an instantiation os that
   * thread manager, which can be used to accomplish various threading
   * objectives.
   *
   * @see getThreadManager
   */
  std::shared_ptr<apache::thrift::concurrency::ThreadManager> thread_manager_;
};
}
