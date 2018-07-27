/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/core/process.h"

namespace osquery {

/// The worker_threads define the default thread pool size.
FLAG(int32, worker_threads, 4, "Number of work dispatch threads");


void InterruptableRunnable::interrupt() {
  // Set the service as interrupted.
  if (!interrupted_.exchange(true)) {
    // Tear down the service's resources such that exiting the expected run
    // loop within ::start does not need to.
    stop();
    std::lock_guard<std::mutex> lock(condition_lock);
    // Cancel the run loop's pause request.
    condition_.notify_one();
  }
}

bool InterruptableRunnable::interrupted() {
  return interrupted_;
}

void InterruptableRunnable::pauseMilli(std::chrono::milliseconds milli) {
  std::unique_lock<std::mutex> lock(condition_lock);
  if (!interrupted_) {
    condition_.wait_for(lock, milli);
  }
}

void InternalRunnable::run() {
  run_ = true;
  setThreadName(name());
  start();

  // The service is complete.
  Dispatcher::removeService(this);
}

Dispatcher& Dispatcher::instance() {
  static Dispatcher instance;
  return instance;
}

size_t Dispatcher::serviceCount() const {
  ReadLock lock(mutex_);
  return services_.size();
}

Status Dispatcher::addService(InternalRunnableRef service) {
  if (service->hasRun()) {
    return Status(1, "Cannot schedule a service twice");
  }

  auto& self = instance();
  if (self.stopping_) {
    // Cannot add a service while the dispatcher is stopping and no joins
    // have been requested.
    return Status(1, "Cannot add service, dispatcher is stopping");
  }

  auto thread = std::make_unique<std::thread>(
      std::bind(&InternalRunnable::run, &*service));

  DLOG(INFO) << "Adding new service: " << service->name() << " ("
             << service.get() << ") to thread: " << thread->get_id() << " ("
             << thread.get() << ") in process " << platformGetPid();
  {
    WriteLock lock(self.mutex_);

    self.service_threads_.push_back(std::move(thread));
    self.services_.push_back(std::move(service));
  }
  return Status(0, "OK");
}

void Dispatcher::removeService(const InternalRunnable* service) {
  auto& self = Dispatcher::instance();
  WriteLock lock(self.mutex_);

  // Remove the service.
  self.services_.erase(
      std::remove_if(self.services_.begin(),
                     self.services_.end(),
                     [service](const InternalRunnableRef& target) {
                       return (target.get() == service);
                     }),
      self.services_.end());
}

inline static void assureRun(const InternalRunnableRef& service) {
  while (true) {
    // Wait for each thread's entry point (start) meaning the thread context
    // was allocated and (run) was called by std::thread started.
    if (service->hasRun()) {
      break;
    }
    // We only need to check if std::terminate is called very quickly after
    // the std::thread is created.
    sleepFor(20);
  }
}

void Dispatcher::joinServices() {
  auto& self = instance();
  DLOG(INFO) << "Thread: " << std::this_thread::get_id()
             << " requesting a join";

  // Stops when service_threads_ is empty. Before stopping and releasing of the
  // lock, empties services_ .
  while (1) {
    InternalThreadRef thread = nullptr;
    {
      WriteLock lock(self.mutex_);
      if (!self.service_threads_.empty()) {
        thread = std::move(self.service_threads_.back());
        self.service_threads_.pop_back();
      } else {
        self.services_.clear();
        break;
      }
    }
    if (thread != nullptr) {
      thread->join();
      DLOG(INFO) << "Service thread: " << thread.get() << " has joined";
    }
  }

  self.stopping_ = false;
  DLOG(INFO) << "Services and threads have been cleared";
}

Dispatcher::~Dispatcher() {
  stopServices();
  joinServices();
}

void Dispatcher::stopServices() {
  auto& self = instance();
  self.stopping_ = true;

  WriteLock lock(self.mutex_);
  DLOG(INFO) << "Thread: " << std::this_thread::get_id()
             << " requesting a stop";
  for (const auto& service : self.services_) {
    assureRun(service);
    service->interrupt();
    DLOG(INFO) << "Service: " << service.get() << " has been interrupted";
  }
}
} // namespace osquery
