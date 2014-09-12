// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <thrift/concurrency/Thread.h>
#include <thrift/concurrency/PosixThreadFactory.h>
#include <thrift/concurrency/ThreadManager.h>

#include "osquery/status.h"

namespace osquery {

// kDefaultThreadPoolSize represents the amount of threads that the thread pool
// will be created with if not otherwise specified
extern const int kDefaultThreadPoolSize;

// Dispatcher is a singleton that exposes the osqueryd work dispatcher and
// thread
// pool
class Dispatcher {
 public:
  // getInstance returns a singleton instance of Dispatcher.
  static std::shared_ptr<Dispatcher> getInstance();

  // add a task to the dispatcher
  Status add(std::shared_ptr<apache::thrift::concurrency::Runnable> task);

  // getter for the thread manager instance.
  std::shared_ptr<apache::thrift::concurrency::ThreadManager>
  getThreadManager();

  // Joins the thread manager. This is the same as stop, except that it will
  // block until all the workers have finished their work. At that point
  // the ThreadManager will transition into the STOPPED state.
  void join();

  // get the current state of the thread manager
  apache::thrift::concurrency::ThreadManager::STATE state() const;

  // add a worker thread
  void addWorker(size_t value = 1);

  // remove a worker thread
  void removeWorker(size_t value = 1);

  // Gets the current number of idle worker threads
  size_t idleWorkerCount() const;

  // Gets the current number of total worker threads
  size_t workerCount() const;

  // Gets the current number of pending tasks
  size_t pendingTaskCount() const;

  // Gets the current number of pending and executing tasks
  size_t totalTaskCount() const;

  // Gets the maximum pending task count.  0 indicates no maximum
  size_t pendingTaskCountMax() const;

  // Gets the number of tasks which have been expired without being run.
  size_t expiredTaskCount() const;

 private:
  // since instances of Dispatcher should only be created via getInstance(),
  // Dispatcher's constructor is private
  Dispatcher();

 private:
  std::shared_ptr<apache::thrift::concurrency::ThreadManager> threadManager;
};
}
