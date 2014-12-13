// Copyright 2004-present Facebook. All Rights Reserved.

#include <glog/logging.h>

#include <osquery/dispatcher.h>
#include <osquery/flags.h>

#include "osquery/core/conversions.h"

using namespace apache::thrift::concurrency;

namespace osquery {

/// The worker_threads define the default thread pool size.
DEFINE_osquery_flag(int32,
                    worker_threads,
                    4,
                    "The number of threads to use for the work dispatcher");

Dispatcher& Dispatcher::getInstance() {
  static Dispatcher d;
  return d;
}

Dispatcher::Dispatcher() {
#ifdef FBOSQUERY
  thread_manager_ = ThreadManager::newSimpleThreadManager(
      (size_t)FLAGS_worker_threads, 0);
  auto threadFactory =
      std::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
#else
  thread_manager_ = boost_to_std_shared_ptr(
      ThreadManager::newSimpleThreadManager((size_t)FLAGS_worker_threads, 0));
  auto threadFactory =
      boost::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
#endif
  thread_manager_->threadFactory(threadFactory);
  thread_manager_->start();
}

Status Dispatcher::add(std::shared_ptr<Runnable> task) {
  try {
#ifdef FBOSQUERY
    thread_manager_->add(task, 0, 0);
#else
    thread_manager_->add(std_to_boost_shared_ptr(task), 0, 0);
#endif
  } catch (std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

std::shared_ptr<ThreadManager> Dispatcher::getThreadManager() {
  return thread_manager_;
}

void Dispatcher::join() { thread_manager_->join(); }

ThreadManager::STATE Dispatcher::state() const {
  return thread_manager_->state();
}

void Dispatcher::addWorker(size_t value) { thread_manager_->addWorker(value); }

void Dispatcher::removeWorker(size_t value) {
  thread_manager_->removeWorker(value);
}

size_t Dispatcher::idleWorkerCount() const {
  return thread_manager_->idleWorkerCount();
}

size_t Dispatcher::workerCount() const {
  return thread_manager_->workerCount();
}

size_t Dispatcher::pendingTaskCount() const {
  return thread_manager_->pendingTaskCount();
}

size_t Dispatcher::totalTaskCount() const {
  return thread_manager_->totalTaskCount();
}

size_t Dispatcher::pendingTaskCountMax() const {
  return thread_manager_->pendingTaskCountMax();
}

size_t Dispatcher::expiredTaskCount() const {
  return thread_manager_->expiredTaskCount();
}
}
