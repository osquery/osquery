/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/dispatcher/dispatcher.h"

namespace osquery {

/// The worker_threads define the default thread pool size.
FLAG(int32, worker_threads, 4, "Number of work dispatch threads");

/// Cancel the pause request.
void RunnerInterruptPoint::cancel() {
  WriteLock lock(mutex_);
  stop_ = true;
  condition_.notify_all();
}

/// Pause until the requested millisecond delay has elapsed or a cancel.
void RunnerInterruptPoint::pause(size_t milli) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (stop_ ||
      condition_.wait_for(lock, std::chrono::milliseconds(milli)) ==
          std::cv_status::no_timeout) {
    stop_ = false;
    throw RunnerInterruptError();
  }
}

void InternalRunnable::pauseMilli(size_t milli) {
  try {
    point_.pause(milli);
  } catch (const RunnerInterruptError&) {
    // The pause request was canceled.
  }
}

Status Dispatcher::addService(InternalRunnableRef service) {
  if (service->hasRun()) {
    return Status(1, "Cannot schedule a service twice");
  }

  auto& self = instance();
  auto thread = std::make_shared<std::thread>(
      std::bind(&InternalRunnable::run, &*service));
  self.service_threads_.push_back(thread);
  self.services_.push_back(std::move(service));
  return Status(0, "OK");
}

void Dispatcher::joinServices() {
  for (auto& thread : instance().service_threads_) {
    // Boost threads would have been interrupted, and joined using the
    // provided thread instance.
    thread->join();
  }

  instance().services_.clear();
  instance().service_threads_.clear();
}

void Dispatcher::stopServices() {
  auto& self = instance();
  for (const auto& service : self.services_) {
    while (true) {
      // Wait for each thread's entry point (start) meaning the thread context
      // was allocated and (run) was called by std::thread started.
      if (service->hasRun()) {
        break;
      }
      // We only need to check if std::terminate is called very quickly after
      // the std::thread is created.
      ::usleep(200);
    }
    service->interrupt();
  }
}
}
