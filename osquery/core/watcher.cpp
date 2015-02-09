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

#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/watcher.h"

extern char** environ;

namespace fs = boost::filesystem;

namespace osquery {

const std::map<WatchdogLimitType, std::vector<size_t> > kWatchdogLimits = {
    {MEMORY_LIMIT, {50, 20, 10}},
    {UTILIZATION_LIMIT, {90, 70, 60}},
    // Number of seconds the worker should run, else consider the exit fatal.
    {RESPAWN_LIMIT, {20, 20, 20}},
    // If the worker respawns too quickly, backoff on creating additional.
    {RESPAWN_DELAY, {5, 5, 5}},
    // Seconds of tolerable sustained latency.
    {LATENCY_LIMIT, {5, 5, 3}},
    // How often to poll for performance limit violations.
    {INTERVAL, {3, 3, 3}}, };

DEFINE_osquery_flag(
    int32,
    watchdog_level,
    1,
    "Performance limit level (0=loose, 1=normal, 2=restrictive)");

DEFINE_osquery_flag(bool,
                    disable_watchdog,
                    false,
                    "Disable userland watchdog process");

bool Watcher::ok() {
  ::sleep(getWorkerLimit(INTERVAL));
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
  BIGINT_LITERAL footprint, user_time, system_time;
  // IV is the check interval in seconds, and utilization is set per-second.
  auto iv = getWorkerLimit(INTERVAL);

  try {
    user_time = AS_LITERAL(BIGINT_LITERAL, rows[0].at("user_time")) / iv;
    system_time = AS_LITERAL(BIGINT_LITERAL, rows[0].at("system_time")) / iv;
    footprint = AS_LITERAL(BIGINT_LITERAL, rows[0].at("phys_footprint"));
  } catch (const std::exception& e) {
    sustained_latency_ = 0;
  }

  if (current_user_time_ + getWorkerLimit(UTILIZATION_LIMIT) < user_time ||
      current_system_time_ + getWorkerLimit(UTILIZATION_LIMIT) < system_time) {
    sustained_latency_++;
  } else {
    sustained_latency_ = 0;
  }

  current_user_time_ = user_time;
  current_system_time_ = system_time;

  if (sustained_latency_ * iv >= getWorkerLimit(LATENCY_LIMIT)) {
    LOG(WARNING) << "osqueryd worker system performance limits exceeded";
    return false;
  }

  if (footprint > getWorkerLimit(MEMORY_LIMIT) * 1024 * 1024) {
    LOG(WARNING) << "osqueryd worker memory limits exceeded";
    return false;
  }

  // The worker is sane, no action needed.
  return true;
}

void Watcher::createWorker() {
  if (last_respawn_time_ > getUnixTime() - getWorkerLimit(RESPAWN_LIMIT)) {
    LOG(WARNING) << "osqueryd worker respawning too quickly";
    ::sleep(getWorkerLimit(RESPAWN_DELAY));
  }

  worker_ = fork();
  if (worker_ < 0) {
    // Unrecoverable error, cannot create a worker process.
    LOG(ERROR) << "osqueryd could not create a worker process";
    ::exit(EXIT_FAILURE);
  } else if (worker_ == 0) {
    // This is the new worker process, no watching needed.
    setenv("OSQUERYD_WORKER", std::to_string(getpid()).c_str(), 1);
    fs::path exec_path(fs::initial_path<fs::path>());
    exec_path = fs::system_complete(fs::path(argv_[0]));
    execve(exec_path.string().c_str(), argv_, environ);
    // Code will never reach this point.
    ::exit(EXIT_FAILURE);
  }

  VLOG(1) << "osqueryd watcher (" << getpid() << ") executing worker ("
          << worker_ << ")";
}

void Watcher::resetCounters() {
  // Reset the monitoring counters for the watcher.
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

  // Start a watcher watcher thread to exit the process if the watcher exits.
  Dispatcher::getInstance().addService(
      std::make_shared<WatcherWatcherRunner>(getppid()));
}

bool isOsqueryWorker() {
  return (getenv("OSQUERYD_WORKER") != nullptr);
}

void WatcherWatcherRunner::enter() {
  while (true) {
    if (getppid() != watcher_) {
      // Watcher died, the worker must follow.
      VLOG(1) << "osqueryd worker (" << getpid()
              << ") detected killed watcher (" << watcher_ << ")";
      ::exit(EXIT_SUCCESS);
    }
    interruptableSleep(getWorkerLimit(INTERVAL) * 1000);
  }
}

size_t getWorkerLimit(WatchdogLimitType name, int level) {
  if (kWatchdogLimits.count(name) == 0) {
    return 0;
  }

  // If no level was provided then use the default (config/switch).
  if (level == -1) {
    level = FLAGS_watchdog_level;
  }
  if (level > 3) {
    return kWatchdogLimits.at(name).back();
  }
  return kWatchdogLimits.at(name).at(level);
}

void initWorkerWatcher(const std::string& name, int argc, char* argv[]) {
  // The watcher will forever monitor and spawn additional workers.
  Watcher watcher(argc, argv);
  watcher.setWorkerName(name);

  if (isOsqueryWorker()) {
    // Do not start watching/spawning if this process is a worker.
    watcher.initWorker();
  } else {
    do {
      if (!watcher.watch()) {
        // The watcher failed, create a worker.
        watcher.createWorker();
        watcher.resetCounters();
      }
    } while (watcher.ok());

    // Executation should never reach this point.
    ::exit(EXIT_FAILURE);
  }
}
}
