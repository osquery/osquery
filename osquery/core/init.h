
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/info/tool_type.h>
#include <osquery/utils/mutex.h>

#include <boost/core/noncopyable.hpp>

#include <functional>
#include <string>

namespace osquery {

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

  /**
   * @brief Move a function callable into the initializer to be called.
   *
   * Install an optional platform method to call when waiting for shutdown.
   * This exists for Windows when the daemon must wait for the service to stop.
   */
  void installShutdown(std::function<void()>& handler);

  /// Assume initialization finished, start work.
  void start() const;

 public:
  /**
   * @brief Forcefully request the application to stop.
   *
   * Since all osquery tools may implement various 'dispatched' services in the
   * form of event handler threads or thrift service and client pools, a stop
   * request should behave nicely and request these services stop.
   *
   * Use shutdown whenever you would normally call stdlib exit.
   *
   * @param retcode the requested return code for the process.
   */
  static void requestShutdown(int retcode = EXIT_SUCCESS);

  /**
   * @brief Forcefully request the application to stop.
   *
   * See #requestShutdown, this overloaded alternative allows the caller to
   * also log a reason/message to the system log. This is intended for extreme
   * failure cases and thus requires an explicit error code.
   *
   * @param retcode the request return code for the process.
   * @param system_log A log line to write to the system's log.
   */
  static void requestShutdown(int retcode, const std::string& system_log);

  /// Exit immediately without requesting the dispatcher to stop.
  static void shutdown(int retcode = EXIT_SUCCESS);

  /**
   * @brief Cleanly wait for all services and components to shutdown.
   *
   * Enter a join of all services followed by a sync wait for event loops,
   * then it shuts down all the components.
   * If the main thread is out of actions it can call #waitThenShutdown.
   */
  static void waitThenShutdown();

  /**
   * @brief Check is a process is an osquery watcher.
   *
   * Is watcher is different from the opposite of isWorker. An osquery process
   * may have disabled the watchdog so the parent could be doing the work or
   * the worker child.
   */
  static bool isWatcher();

 public:
  /// Initialize this process as an osquery daemon worker.
  void initWorker(const std::string& name) const;

  /// Initialize the osquery watcher, optionally spawn a worker.
  void initWatcher() const;

  /// This pauses the watchdog process until the watcher thread stops.
  void waitForWatcher() const;

 private:
  /// Set and wait for an active plugin optionally broadcasted.
  void initActivePlugin(const std::string& type, const std::string& name) const;

 private:
  /// A saved, mutable, reference to the process's argc.
  int* argc_{nullptr};

  /// A saved, mutable, reference to the process's argv.
  char*** argv_{nullptr};

  /// The deduced program name determined by executing path.
  std::string binary_;

  /// A platform specific callback to wait for shutdown.
  static std::function<void()> shutdown_;

  /// Mutex to protect use of the shutdown callable.
  static RecursiveMutex shutdown_mutex_;
};
} // namespace osquery
