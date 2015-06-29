/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/date_time/posix_time/posix_time.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/dispatcher/dispatcher.h"

using namespace apache::thrift::concurrency;

namespace osquery {

/// The worker_threads define the default thread pool size.
FLAG(int32, worker_threads, 1, "Number of work dispatch threads");

void interruptableSleep(size_t milli) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(milli));
}

Dispatcher::Dispatcher() {
  thread_manager_ = InternalThreadManager::newSimpleThreadManager(
          (size_t)FLAGS_worker_threads, 0);
  auto thread_factory = ThriftThreadFactory(new PosixThreadFactory());
  thread_manager_->threadFactory(thread_factory);
  thread_manager_->start();
}

Dispatcher::~Dispatcher() { join(); }

Status Dispatcher::add(ThriftInternalRunnableRef task) {
  auto& self = instance();
  try {
    if (self.state() != InternalThreadManager::STARTED) {
      self.thread_manager_->start();
    }
    instance().thread_manager_->add(task, 0, 0);
  } catch (std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status Dispatcher::addService(InternalRunnableRef service) {
  if (service->hasRun()) {
    return Status(1, "Cannot schedule a service twice");
  }

  auto& self = instance();
  auto thread = std::make_shared<boost::thread>(
      boost::bind(&InternalRunnable::run, &*service));
  self.service_threads_.push_back(std::move(thread));
  self.services_.push_back(std::move(service));
  return Status(0, "OK");
}

InternalThreadManagerRef Dispatcher::getThreadManager() const {
  return instance().thread_manager_;
}

void Dispatcher::join() {
  if (instance().thread_manager_ != nullptr) {
    instance().thread_manager_->stop();
    instance().thread_manager_->join();
  }
}

void Dispatcher::joinServices() {
  for (auto& thread : instance().service_threads_) {
    thread->join();
  }
}

void Dispatcher::stopServices() {
  auto& self = instance();
  for (const auto& service : self.services_) {
    while (true) {
      // Wait for each thread's entry point (start) meaning the thread context
      // was allocated and (run) was called by boost::thread started.
      if (service->hasRun()) {
        break;
      }
      // We only need to check if std::terminate is called very quickly after
      // the boost::thread is created.
      ::usleep(200);
    }
    service->stop();
  }

  for (auto& thread : self.service_threads_) {
    thread->interrupt();
  }
}

InternalThreadManager::STATE Dispatcher::state() const {
  return instance().thread_manager_->state();
}

void Dispatcher::addWorker(size_t value) {
  instance().thread_manager_->addWorker(value);
}

void Dispatcher::removeWorker(size_t value) {
  instance().thread_manager_->removeWorker(value);
}

size_t Dispatcher::idleWorkerCount() const {
  return instance().thread_manager_->idleWorkerCount();
}

size_t Dispatcher::workerCount() const {
  return instance().thread_manager_->workerCount();
}

size_t Dispatcher::pendingTaskCount() const {
  return instance().thread_manager_->pendingTaskCount();
}

size_t Dispatcher::totalTaskCount() const {
  return instance().thread_manager_->totalTaskCount();
}

size_t Dispatcher::pendingTaskCountMax() const {
  return instance().thread_manager_->pendingTaskCountMax();
}

size_t Dispatcher::expiredTaskCount() const {
  return instance().thread_manager_->expiredTaskCount();
}
}
