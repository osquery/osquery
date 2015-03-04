/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include <unistd.h>

#include <osquery/flags.h>

#include "osquery/dispatcher/dispatcher.h"

namespace osquery {

DECLARE_bool(disable_watchdog);

enum WatchdogLimitType {
  MEMORY_LIMIT,
  UTILIZATION_LIMIT,
  RESPAWN_LIMIT,
  RESPAWN_DELAY,
  LATENCY_LIMIT,
  INTERVAL,
};

class Watcher {
 public:
  Watcher(int argc, char** argv) : worker_(0), argc_(argc), argv_(argv) {
    resetCounters();
    last_respawn_time_ = 0;
  }

  void setWorkerName(const std::string& name) { name_ = name; }
  const std::string& getWorkerName() { return name_; }

  /// Boilerplate function to sleep for some configured latency
  bool ok();
  /// Begin the worker-watcher process.
  bool watch();
  /// Fork a worker process.
  void createWorker();
  /// If the process is a worker, clean up identification.
  void initWorker();
  void resetCounters();

 private:
  /// Inspect into the memory, CPU, and other worker process states.
  bool isWorkerSane();
  /// If a worker as otherwise gone insane, stop it.
  void stopWorker();

 private:
  size_t sustained_latency_;
  size_t current_user_time_;
  size_t current_system_time_;
  size_t last_respawn_time_;

 private:
  /// Keep the single worker process/thread ID for inspection.
  pid_t worker_;
  /// Keep the invocation daemon's argc to iterate through argv.
  int argc_;
  /// When a worker child is spawned the argv will be scrubed.
  char** argv_;
  /// When a worker child is spawned the process name will be changed.
  std::string name_;
};

/// The WatcherWatcher is spawned within the worker and watches the watcher.
class WatcherWatcherRunner : public InternalRunnable {
 public:
  explicit WatcherWatcherRunner(pid_t watcher) : watcher_(watcher) {}
  void enter();

 private:
  pid_t watcher_;
};

/// Get a performance limit by name and optional level.
size_t getWorkerLimit(WatchdogLimitType limit, int level = -1);
}
