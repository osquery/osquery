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

#include <osquery/dispatcher.h>
#include <osquery/flags.h>

namespace osquery {

DECLARE_bool(disable_watchdog);

class Watcher {
 public:
  Watcher(int argc, char* argv[]) : worker_(0), argc_(argc), argv_(argv) {
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
  WatcherWatcherRunner(pid_t watcher) : watcher_(watcher) {}
  void enter();

 private:
  pid_t watcher_;
};

/// Check if the current process is already a worker.
bool isOsqueryWorker();

/**
 * @brief Daemon tools may want to continually spawn worker processes
 * and monitor their utilization.
 *
 * A daemon may call initWorkerWatcher to begin watching child daemon
 * processes until it-itself is unscheduled. The basic guarentee is that only
 * workers will return from the function.
 *
 * The worker-watcher will implement performance bounds on CPU utilization
 * and memory, as well as check for zombie/defunct workers and respawn them
 * if appropriate. The appropriateness is determined from heuristics around
 * how the worker exitted. Various exit states and velocities may cause the
 * watcher to resign.
 *
 * @param name The name of the worker process.
 * @param argc The daemon's argc.
 * @param argv The daemon's volitle argv.
 */
void initWorkerWatcher(const std::string& name, int argc, char* argv[]);
}
