/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <csignal>
#include <memory>
#include <mutex>
#include <string>

#include <boost/core/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/utils/info/tool_type.h>
#include <osquery/utils/mutex.h>
#include <osquery/utils/system/system.h>

namespace osquery {

class Status;

using ModuleHandle = void*;

class Initializer : private boost::noncopyable {
 public:
  /**
   * @brief Sets up various aspects of osquery execution state.
   *
   * osquery needs a few things to happen as soon as the process begins
   * executing. Initializer takes care of setting up the relevant parameters.
   * Initializer should be called in an executable's `main()` function.
   *
   * @param argc the number of elements in argv
   * @param argv the command-line arguments passed to `main()`
   * @param tool the type of osquery main (daemon, shell, test, extension).
   * @param init_glog whether to start google logging module (it can be
   * initialized at most once)
   */
  Initializer(int& argc,
              char**& argv,
              ToolType tool = ToolType::TEST,
              bool init_glog = true);

  ~Initializer();

  /**
   * @brief Sets up the process as an osquery daemon.
   *
   * A daemon has additional constraints, it can use a process mutex, check
   * for sane/non-default configurations, etc.
   */
  void initDaemon() const;

  /**
   * @brief Sets up the process as an osquery shell.
   *
   * The shell is lighter than a daemon and disables (by default) features.
   */
  void initShell() const;

  /**
   * @brief Daemon tools may want to continually spawn worker processes
   * and monitor their utilization.
   *
   * A daemon may call initWorkerWatcher to begin watching child daemon
   * processes until it-itself is unscheduled. The basic guarantee is that only
   * workers will return from the function.
   *
   * The worker-watcher will implement performance bounds on CPU utilization
   * and memory, as well as check for zombie/defunct workers and respawn them
   * if appropriate. The appropriateness is determined from heuristics around
   * how the worker exited. Various exit states and velocities may cause the
   * watcher to resign.
   *
   * @param name The name of the worker process.
   */
  void initWorkerWatcher(const std::string& name = "") const;

  /// Assume initialization finished, start work.
  void start() const;

  /**
   * @brief Cleanly shutdown all services and components.
   *
   * Issue interrupt/stop requests to all service threads, join them, then
   * stop the eventing system, database usage, and run any platform-specific
   * teardown logic.
   *
   * If a request to shutdown stored a non-0 return code, that will override
   * the input return code if the input is 0. If the caller assumes success
   * and something else indicated failure we return with the failure code.
   *
   * If the main thread is out of actions it can call #shutdown.
   *
   * @param retcode Caller (main thread's) request return code.
   * @return The most appropriate return code.
   */
  int shutdown(int retcode) const;

  /// For compatibility. See the global method waitForShutdown.
  void waitForShutdown() const;

  /// For compatibility. See the global method requestShutdown.
  static void requestShutdown(int retcode = EXIT_SUCCESS);

  /// For compatibility. See the global method requestShutdown.
  static void requestShutdown(int retcode, const std::string& system_log);

  /// Exit immediately without requesting the dispatcher to stop.
  static void shutdownNow(int retcode = EXIT_SUCCESS);

  /**
   * @brief Check if a process is an osquery worker.
   *
   * By default an osqueryd process will fork/exec then set an environment
   * variable: `OSQUERY_WORKER` while continually monitoring child I/O.
   * The environment variable causes subsequent child processes to skip several
   * initialization steps and jump into extension handling, registry setup,
   * config/logger discovery and then the event publisher and scheduler.
   */
  static bool isWorker();

  /**
   * @brief Check is a process is an osquery watcher.
   *
   * Is watcher is different from the opposite of isWorker. An osquery process
   * may have disabled the watchdog so the parent could be doing the work or
   * the worker child.
   */
  static bool isWatcher();

  /// Initialize this process as an osquery daemon worker.
  void initWorker(const std::string& name) const;

  /// Initialize the osquery watcher, optionally spawn a worker.
  void initWatcher() const;

  /// This pauses the watchdog process until the watcher thread stops.
  void waitForWatcher() const;

  static void resourceLimitHit();
  static bool isResourceLimitHit();

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// Set and wait for an active plugin optionally broadcasted.
  void initActivePlugin(const std::string& type, const std::string& name) const;

  /// A saved, mutable, reference to the process's argc.
  int* argc_{nullptr};

  /// A saved, mutable, reference to the process's argv.
  char*** argv_{nullptr};

  /// The deduced program name determined by executing path.
  std::string binary_;

  /// Is this a worker process
  static bool isWorker_;

  static std::atomic<bool> resource_limit_hit_;
};

/**
 * @brief Generate a new generic UUID
 *
 * @return a string containing a random UUID
 */
std::string generateNewUUID();

/**
 * @brief Getter for an instance uuid
 *
 * @return ok on success and ident is set to the instance uuid, otherwise
 * failure.
 */
Status getInstanceUUID(std::string& ident);

/**
 * @brief Getter for an ephemeral uuid
 *
 * @return ok on success and ident is set to the ephemeral uuid, otherwise
 * failure.
 */
Status getEphemeralUUID(std::string& ident);

/**
 * @brief Getter for a host's uuid.
 *
 * @return ok on success and ident is set to the host's uuid, otherwise failure.
 */
Status getHostUUID(std::string& ident);

/**
 * @brief Determine whether the UUID is a placeholder.
 *
 * Some motherboards report placeholder UUIDs which, from point of view of being
 * unique, are useless. This method checks the provided UUID against a list of
 * known placeholders so that it can be treated as invalid. This method ignores
 * case.
 *
 * @param uuid UUID to test.
 * @return true if UUID is a placeholder and false otherwise.
 */
bool isPlaceholderHardwareUUID(const std::string& uuid);

/**
 * @brief generate a uuid to uniquely identify this machine
 *
 * @return uuid string to identify this machine
 */
std::string generateHostUUID();

/**
 * @brief Get a configured UUID/name that uniquely identify this machine
 *
 * @return string to identify this machine
 */
std::string getHostIdentifier();

/**
 * @brief Getter for determining Admin status
 *
 * @return A bool indicating if the current process is running as admin
 */
bool isUserAdmin();

/**
 * @brief Set the name of the thread
 *
 * @return If the name was set successfully
 */
Status setThreadName(const std::string& name);

/// Get the osquery tool start time.
uint64_t getStartTime();

/// Set the osquery tool start time.
void setStartTime(uint64_t st);

/**
 * @brief Initialize any platform dependent libraries or objects.
 *
 * On windows, we require the COM libraries be initialized just once.
 */
void platformSetup();

/**
 * @brief Before ending, tear down any platform specific setup.
 *
 * On windows, we require the COM libraries be initialized just once.
 */
void platformTeardown();

bool checkPlatform(const std::string& platform);
} // namespace osquery
