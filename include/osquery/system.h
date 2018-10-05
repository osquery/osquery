/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <csignal>
#include <mutex>
#include <string>

#include <osquery/core.h>
#include <osquery/mutex.h>

#ifdef WIN32
#include <osquery/windows/system.h>
#else
#include <osquery/posix/system.h>
#endif

namespace osquery {

class Status;

/**
 * @brief The requested exit code.
 *
 * Use Initializer::shutdown to request shutdown in most cases.
 * This will raise a signal to the main thread requesting the dispatcher to
 * interrupt all services. There is a thread requesting a join of all services
 * that will continue the shutdown process.
 */
extern volatile std::sig_atomic_t kExitCode;

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
   */
  Initializer(int& argc, char**& argv, ToolType tool = ToolType::TEST);

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
   * Enter a join of all services followed by a sync wait for event loops.
   * If the main thread is out of actions it can call #waitForShutdown.
   */
  static void waitForShutdown();

  /**
   * @brief Initialize any platform dependent libraries or objects
   *
   * On windows, we require the COM libraries be initialized just once
   */
  static void platformSetup();

  /**
   * @brief Before ending, tear down any platform specific setup
   *
   * On windows, we require the COM libraries be initialized just once
   */
  static void platformTeardown();

  /// Check the program is the osquery daemon.
  static bool isDaemon() {
    return kToolType == ToolType::DAEMON;
  }

  /// Check the program is the osquery shell.
  static bool isShell() {
    return kToolType == ToolType::SHELL;
  }

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

/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
std::string getHostname();

/**
 * @brief Getter for a host's fully qualified domain name
 *
 * @return a string representation of the hosts fully qualified domain name
 * if the host is joined to a domain, otherwise it simply returns the hostname
 */
std::string getFqdn();

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
 * @brief Converts struct tm to a size_t
 *
 * @param tm_time the time/date to convert to UNIX epoch time
 *
 * @return an int representing the UNIX epoch time of the struct tm
 */
size_t toUnixTime(const struct tm* tm_time);

/**
 * @brief Getter for the current UNIX time.
 *
 * @return an int representing the amount of seconds since the UNIX epoch
 */
size_t getUnixTime();

/**
 * @brief Converts a struct tm into a human-readable format. This expected the
 * struct tm to be already in UTC time/
 *
 * @param tm_time the time/date to convert to ASCII
 *
 * @return the data/time of tm_time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string toAsciiTime(const struct tm* tm_time);

/**
 * @brief Converts a struct tm to ASCII time UTC by converting the tm_time to
 * epoch and then running gmtime() on the new epoch
 *
 * @param tm_time the local time/date to covert to UTC ASCII time
 *
 * @return the data/time of tm_time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string toAsciiTimeUTC(const struct tm* tm_time);

/**
 * @brief Getter for the current time, in a human-readable format.
 *
 * @return the current date/time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string getAsciiTime();

/**
 * @brief Create a pid file
 *
 * @return A status object indicating the success or failure of the operation
 */
Status createPidFile();

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

bool checkPlatform(const std::string& platform);
} // namespace osquery
