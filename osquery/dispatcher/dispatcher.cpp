// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/dispatcher.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/core/conversions.h"

using namespace apache::thrift::concurrency;

namespace osquery {

const int kDefaultThreadPoolSize = 4;

DEFINE_int32(worker_threads,
             kDefaultThreadPoolSize,
             "The number of threads to use for the work dispatcher");

std::shared_ptr<Dispatcher> Dispatcher::getInstance() {
  static std::shared_ptr<Dispatcher> q =
      std::shared_ptr<Dispatcher>(new Dispatcher());
  return q;
}

Dispatcher::Dispatcher() {
  threadManager = boost_to_std_shared_ptr(
      ThreadManager::newSimpleThreadManager(FLAGS_worker_threads, 0));
  auto threadFactory =
      boost::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
  threadManager->threadFactory(threadFactory);
  threadManager->start();
}

Status Dispatcher::add(std::shared_ptr<Runnable> task) {
  try {
    threadManager->add(std_to_boost_shared_ptr(task), 0, 0);
  }
  catch (std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

std::shared_ptr<ThreadManager> Dispatcher::getThreadManager() {
  return threadManager;
}

void Dispatcher::join() { threadManager->join(); }

ThreadManager::STATE Dispatcher::state() const {
  return threadManager->state();
}

void Dispatcher::addWorker(size_t value) { threadManager->addWorker(value); }

void Dispatcher::removeWorker(size_t value) {
  threadManager->removeWorker(value);
}

size_t Dispatcher::idleWorkerCount() const {
  return threadManager->idleWorkerCount();
}

size_t Dispatcher::workerCount() const { return threadManager->workerCount(); }

size_t Dispatcher::pendingTaskCount() const {
  return threadManager->pendingTaskCount();
}

size_t Dispatcher::totalTaskCount() const {
  return threadManager->totalTaskCount();
}

size_t Dispatcher::pendingTaskCountMax() const {
  return threadManager->pendingTaskCountMax();
}

size_t Dispatcher::expiredTaskCount() const {
  return threadManager->expiredTaskCount();
}
}
