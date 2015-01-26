/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <cstring>
#include <sstream>

#include <sys/wait.h>
#include <signal.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/watcher.h"

namespace osquery {

#define WORKER_MEMORY_LIMIT (20 * 1024 * 1024)
#define WORKER_UTILIZATION_LIMIT 60
#define WORKER_RESPAWN_LIMIT 20
#define WORKER_RESPAWN_DELAY 5
#define WORKER_LATENCY_LIMIT 5

bool Watcher::ok() {
  ::sleep(1);
  return (worker_ >= 0);
}

bool Watcher::watch() {
  int status;
  pid_t result = waitpid(worker_, &status, WNOHANG);
  if (worker_ == 0 || result == worker_) {
    // Worker does not exist or never existed.
    return false;
  } else if (result == 0) {
    // If the inspect finds problems it will stop/restart the worker.
    if (!isWorkerSane()) {
      stopWorker();
      return false;
    }
  }
  return true;
}

void Watcher::stopWorker() {
  kill(worker_, SIGKILL);
  worker_ = 0;
  // Clean up the defunct (zombie) process.
  waitpid(-1, 0, 0);
}

bool Watcher::isWorkerSane() {
  auto rows =
      SQL::selectAllFrom("processes", "pid", tables::EQUALS, INTEGER(worker_));
  if (rows.size() == 0) {
    // Could not find worker process?
    return false;
  }

  // Compare CPU utilization since last check.
  size_t user_time = AS_LITERAL(INTEGER_LITERAL, rows[0].at("user_time"));
  size_t system_time = AS_LITERAL(INTEGER_LITERAL, rows[0].at("system_time"));
  if (current_user_time_ + WORKER_UTILIZATION_LIMIT < user_time ||
      current_system_time_ + WORKER_UTILIZATION_LIMIT < system_time) {
    sustained_latency_++;
  } else {
    sustained_latency_ = 0;
  }
  current_user_time_ = user_time;
  current_system_time_ = system_time;

  if (sustained_latency_ >= WORKER_LATENCY_LIMIT) {
    LOG(WARNING) << "osqueryd worker system performance limits exceeded";
    return false;
  }

  size_t footprint = AS_LITERAL(INTEGER_LITERAL, rows[0].at("phys_footprint"));
  if (footprint > WORKER_MEMORY_LIMIT) {
    LOG(WARNING) << "osqueryd worker memory limits exceeded";
    return false;
  }

  // The worker is sane, no action needed.
  return true;
}

bool Watcher::createWorker() {
  if (last_respawn_time_ > getUnixTime() - WORKER_RESPAWN_LIMIT) {
    LOG(WARNING) << "osqueryd worker respawning too quickly";
    ::sleep(WORKER_RESPAWN_DELAY);
  }

  worker_ = fork();
  if (worker_ < 0) {
    // Unrecoverable error, cannot create a worker process.
    LOG(ERROR) << "osqueryd could not create a worker process";
    ::exit(EXIT_FAILURE);
  } else if (worker_ == 0) {
    // This is the new worker process, no watching needed.
    initWorker();
    return true;
  }

  // This is still the watcher, reset performance monitoring.
  resetCounters();
  return false;
}

void Watcher::resetCounters() {
  sustained_latency_ = 0;
  current_user_time_ = 0;
  current_system_time_ = 0;
  last_respawn_time_ = getUnixTime();
}

void Watcher::initWorker() {
  // Set the worker's process name.
  size_t name_size = strlen(argv_[0]);
  for (int i = 0; i < argc_; i++) {
    if (argv_[i] != nullptr) {
      memset(argv_[i], 0, strlen(argv_[i]));
    }
  }
  strncpy(argv_[0], name_.c_str(), name_size);
}

void initWorkerWatcher(const std::string& name, int argc, char* argv[]) {
  // The watcher will forever monitor and spawn additional workers.
  Watcher watcher(argc, argv);
  watcher.setWorkerName(name);

  do {
    if (!watcher.watch()) {
      // The watcher failed, create a worker.
      if (watcher.createWorker()) {
        // This is the execution of the new worker, break out of watching.
        break;
      }
    }
  } while (watcher.ok());
}
}
