/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <string>
#include <thread>

#ifndef WIN32
#include <unistd.h>
#endif

#include <boost/noncopyable.hpp>

#include <osquery/core/flags.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/process/process.h>

namespace osquery {

using ExtensionMap = std::map<std::string, std::shared_ptr<PlatformProcess>>;

DECLARE_bool(disable_watchdog);
DECLARE_int32(watchdog_level);

class WatcherRunner;

/**
 * @brief Categories of process performance limitations.
 *
 * Performance limits are applied by a watcher thread on autoloaded extensions
 * and a optional daemon worker process. The performance types are identified
 * here, and organized into levels. Such that a caller may enforce rigor or
 * relax the performance expectations of a osquery daemon.
 */
enum class WatchdogLimitType {
  MEMORY_LIMIT,
  UTILIZATION_LIMIT,
  RESPAWN_LIMIT,
  RESPAWN_DELAY,
  LATENCY_LIMIT,
  INTERVAL,
};

/**
 * @brief A performance state structure for an autoloaded extension or worker.
 *
 * A watcher thread will continue to check the performance state, and keep a
 * last-checked snapshot for each autoloaded extension and worker process.
 */
struct PerformanceState {
  /// A counter of how many intervals the process exceeded performance limits.
  size_t sustained_latency;
  /// The last checked user CPU time.
  uint64_t user_time;
  /// The last checked system CPU time.
  uint64_t system_time;
  /// A timestamp when the process/worker was last created.
  uint64_t last_respawn_time;

  /// The initial (or as close as possible) process image footprint.
  uint64_t initial_footprint;

  PerformanceState() {
    sustained_latency = 0;
    user_time = 0;
    system_time = 0;
    last_respawn_time = 0;
    initial_footprint = 0;
  }
};

/**
 * @brief Thread-safe watched child process state manager.
 *
 * The Watcher instance is separated from the WatcherRunner thread to allow
 * signals and osquery-introspection to monitor the autoloaded extensions
 * and optional worker stats. A child-process change signal may indicate an
 * autoloaded extension ended. Tables may also report on the historic worker
 * or extension utilizations.
 *
 * Though not critical, it is preferred to remove the extension's broadcasted
 * routes quickly. Locking access to the extensions list between signals and
 * the WatcherRunner thread allows osquery to tearDown registry changes before
 * attempting to respawn an extension process.
 */
class Watcher : private boost::noncopyable {
 public:
  /// Do not request the lock until extensions are used.
  Watcher() : worker_restarts_(0) {
    setWorker(std::make_shared<PlatformProcess>());
  }

  virtual ~Watcher() {}

  /// Become responsible for the worker's fate, but do not guarantee its safety.
  void bindFates() {
    restart_worker_ = false;
  }

  /**
   * @brief Return the state of autoloadable extensions.
   *
   * Some initialization decisions are made based on waiting for plugins to
   * broadcast from potentially-loaded extensions. If no extensions are loaded
   * and an active (selected at command line) plugin is missing, fail quickly.
   */
  static bool hasManagedExtensions();

  /// Check the status of the last worker.
  int getWorkerStatus() const {
    return worker_status_;
  }

  /**
   * @brief Call the loadExtensions global method.
   *
   * The watcher is the only 'user' of autoloadable extensions. It will start
   * each process and optionally monitor the performance.
   */
  void loadExtensions();

 private:
  /// Accessor for the worker process.
  PlatformProcess& getWorker() {
    return *worker_;
  }

  /// Reset counters after a worker exits.
  void resetWorkerCounters(uint64_t respawn_time);

  /// Reset counters for an extension path.
  void resetExtensionCounters(const std::string& extension,
                              uint64_t respawn_time);

  /// Accessor for autoloadable extension paths.
  const ExtensionMap& extensions() const {
    return extensions_;
  }

  /// Lookup extension path from pid.
  std::string getExtensionPath(const PlatformProcess& child);

  /// Remove an autoloadable extension path.
  void removeExtensionPath(const std::string& extension);

  /// Get state information for a worker or extension child.
  PerformanceState& getState(const PlatformProcess& child);
  PerformanceState& getState(const std::string& extension);

  /// Setter for worker process.
  void setWorker(const std::shared_ptr<PlatformProcess>& child) {
    worker_ = child;
  }

  /// Setter for an extension process.
  void setExtension(const std::string& extension,
                    const std::shared_ptr<PlatformProcess>& child);

  /// Reset pid and performance counters for a worker or extension process.
  void reset(const PlatformProcess& child);

  /// Count the number of worker restarts.
  size_t workerRestartCount() const {
    return worker_restarts_;
  }

  /// Check if the worker and watcher's fates are bound.
  bool fatesBound() const {
    return !restart_worker_;
  }

  /// Inform the watcher that the worker restarted without cause.
  void workerRestarted() {
    worker_restarts_++;
  }

  void workerStartTime(uint64_t start_time) {
    worker_start_time_ = start_time;
  }

  uint64_t workerStartTime() {
    return worker_start_time_;
  }

 private:
  /// Performance state for the worker process.
  PerformanceState state_;

  /// Performance states for each autoloadable extension binary.
  std::map<std::string, PerformanceState> extension_states_;

  /// Keep the single worker process/thread ID for inspection.
  std::shared_ptr<PlatformProcess> worker_;

  /// Time the worker was started.
  uint64_t worker_start_time_{0};

  /// Number of worker restarts NOT induced by a watchdog process.
  size_t worker_restarts_{0};

  /// Keep a list of resolved extension paths and their managed pids.
  ExtensionMap extensions_;

  /// Bind the fate of the watcher to the worker.
  std::atomic<bool> restart_worker_{true};

  /// Record the exit status of the most recent worker.
  std::atomic<int> worker_status_{-1};

  /// Used to synchronize a process start with an attempt to stop such process
  std::mutex new_processes_mutex_;

 private:
  friend class WatcherRunner;
  FRIEND_TEST(WatcherTests, test_watcherrunner_unhealthy_delay);
  FRIEND_TEST(WatcherTests, test_watcherrunner_unhealthy);
};

/**
 * @brief The watchdog thread responsible for spawning/monitoring children.
 *
 * The WatcherRunner thread will spawn any autoloaded extensions or optional
 * osquery daemon worker processes. It will then poll for their performance
 * state and kill/respawn osquery child processes if they violate limits.
 */
class WatcherRunner : public InternalRunnable {
 public:
  /**
   * @brief Construct a watcher thread.
   *
   * @param argc The osquery process argc.
   * @param argv The osquery process argv.
   * @param use_worker True if the process should spawn and monitor a worker.
   */
  explicit WatcherRunner(int argc,
                         char** argv,
                         bool use_worker,
                         const std::shared_ptr<Watcher>& watcher);

 private:
  /// Dispatcher (this service thread's) entry point.
  void start() override;

  void stop() override;

  /// Boilerplate function to sleep for some configured latency
  bool ok() const;

  /// Begin the worker-watcher process.
  virtual bool watch(const PlatformProcess& child) const;

  /// Enumerate each extension and check sanity.
  virtual void watchExtensions();

  /// Inspect into the memory, CPU, and other worker/extension process states.
  virtual Status isChildSane(const PlatformProcess& child) const;

  /// Inspect into the memory and CPU of the watcher process.
  virtual Status isWatcherHealthy(const PlatformProcess& watcher,
                                  PerformanceState& watcher_state) const;

  /// Get row data from the processes table for a given pid.
  virtual QueryData getProcessRow(pid_t pid) const;

 private:
  /// Fork and execute a worker process.
  virtual void createWorker();

  /// Fork an extension process.
  virtual void createExtension(const std::string& extension);

  /// Signal the worker or extension process to close cleanly.
  /// If enough time has passed, and the process hasn't closed yet,
  /// the process will be killed.
  /// The force argument is used to request a faster timeout
  /// for the clean shutdown, which is based on the flag
  /// watchdog_forced_shutdown_delay
  virtual void stopChild(const PlatformProcess& child,
                         bool force = false) const;

  virtual void warnWorkerResourceLimitHit(const PlatformProcess& child) const;

  /// Return the time the watchdog is delayed until (from start of watcher).
  uint64_t delayedTime() const;

 private:
  /// For testing only, ask the WatcherRunner to run a start loop once.
  void runOnce() {
    run_once_ = true;
  }

 private:
  /// Keep the invocation daemon's argc to iterate through argv.
  int argc_{0};

  /// When a worker child is spawned the argv will be scrubbed.
  char** argv_{nullptr};

  /// Spawn/monitor a worker process.
  bool use_worker_{false};

  /// If set, the ::start method will run once and return.
  bool run_once_{false};

  /// Similarly to the uncontrolled worker restarted, count each extension.
  std::map<std::string, size_t> extension_restarts_;

  /// Watcher instance.
  std::shared_ptr<Watcher> watcher_{nullptr};

 private:
  FRIEND_TEST(WatcherTests, test_watcherrunner_watch);
  FRIEND_TEST(WatcherTests, test_watcherrunner_stop);
  FRIEND_TEST(WatcherTests, test_watcherrunner_loop);
  FRIEND_TEST(WatcherTests, test_watcherrunner_loop_failure);
  FRIEND_TEST(WatcherTests, test_watcherrunner_loop_disabled);
  FRIEND_TEST(WatcherTests, test_watcherrunner_watcherhealth);
  FRIEND_TEST(WatcherTests, test_watcherrunner_unhealthy_delay);
  FRIEND_TEST(WatcherTests, test_watcherrunner_unhealthy);
};

/// The WatcherWatcher is spawned within the worker and watches the watcher.
class WatcherWatcherRunner : public InternalRunnable {
 public:
  explicit WatcherWatcherRunner(const std::shared_ptr<PlatformProcess>& watcher)
      : InternalRunnable("WatcherWatcherRunner"), watcher_(watcher) {}

  /// Runnable thread's entry point.
  void start() override;

 private:
  /// Parent, or watchdog, process ID.
  std::shared_ptr<PlatformProcess> watcher_;
};

/// Get a performance limit by name and optional level.
uint64_t getWorkerLimit(WatchdogLimitType limit);
} // namespace osquery
