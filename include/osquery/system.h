/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <csignal>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/core.h>

namespace osquery {

/**
 * @brief The requested exit code.
 *
 * Use Initializer::shutdown to request shutdown in most cases.
 * This will raise a signal to the main thread requesting the dispatcher to
 * interrupt all services. There is a thread requesting a join of all services
 * that will continue the shutdown process.
 */
extern volatile std::sig_atomic_t kExitCode;

#ifdef WIN32
/// Unfortunately, pid_t is not defined in Windows, however, DWORD is the
/// most appropriate alternative since process ID on Windows are stored in
/// a DWORD.
using pid_t = unsigned long;
using PlatformPidType = void*;
#else
using PlatformPidType = pid_t;
#endif

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

  /// Assume initialization finished, start work.
  void start() const;

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

 public:
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

  /// Initialize this process as an osquery daemon worker.
  void initWorker(const std::string& name) const;

  /// Initialize the osquery watcher, optionally spawn a worker.
  void initWatcher() const;

  void waitForWatcher() const;

 private:
  /// Set and wait for an active plugin optionally broadcasted.
  void initActivePlugin(const std::string& type, const std::string& name) const;

 private:
  /// A saved, mutable, reference to the process's argc.
  int* argc_{nullptr};

  /// A saved, mutable, reference to the process's argv.
  char*** argv_{nullptr};

  /// The deduced tool type, determined by initializer construction.
  ToolType tool_;

  /// The deduced program name determined by executing path.
  std::string binary_;
};

#ifndef WIN32
class DropPrivileges;
typedef std::shared_ptr<DropPrivileges> DropPrivilegesRef;

class DropPrivileges : private boost::noncopyable {
 public:
  /// Make call sites use 'dropTo' booleans to improve the UI.
  static DropPrivilegesRef get() {
    DropPrivilegesRef handle = DropPrivilegesRef(new DropPrivileges());
    return handle;
  }

  /**
   * @brief Attempt to drop privileges to that of the parent of a given path.
   *
   * This will return false if privileges could not be dropped or there was
   * an previous, and still active, request for dropped privileges.
   *
   * @return success if privileges were dropped, otherwise false.
   */
  bool dropToParent(const boost::filesystem::path& path);

  /// See DropPrivileges::dropToParent but explicitly set the UID and GID.
  bool dropTo(uid_t uid, gid_t gid);

  /// See DropPrivileges::dropToParent but for a user's UID and GID.
  bool dropTo(const std::string& user);

  /// Check if effective privileges do not match real.
  bool dropped() {
    return (getuid() != geteuid() || getgid() != getegid());
  }

  /**
   * @brief The privilege/permissions dropper deconstructor will restore
   * effective permissions.
   *
   * There should only be a single drop of privilege/permission active.
   */
  virtual ~DropPrivileges();

 private:
  DropPrivileges() : dropped_(false), to_user_(0), to_group_(0) {}

  /// Restore groups if dropping consecutively.
  void restoreGroups();

 private:
  /// Boolean to track if this instance needs to restore privileges.
  bool dropped_;

  /// The user this instance dropped privileges to.
  uid_t to_user_;

  /// The group this instance dropped privileges to.
  gid_t to_group_;

  /**
   * @brief If dropping explicitly to a user and group also drop groups.
   *
   * Original process groups before explicitly dropping privileges.
   * On restore, if there are any groups in this list, they will be added
   * to the processes group list.
   */
  gid_t* original_groups_{nullptr};

  /// The size of the original groups to backup when restoring privileges.
  size_t group_size_{0};

 private:
  FRIEND_TEST(PermissionsTests, test_explicit_drop);
  FRIEND_TEST(PermissionsTests, test_path_drop);
  FRIEND_TEST(PermissionsTests, test_nobody_drop);
};
#endif

/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
std::string getHostname();

/**
 * @brief Getter for a host's uuid.
 *
 * @return ok on success and ident is set to the host's uuid, otherwise failure.
 */
Status getHostUUID(std::string& ident);

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
 * @brief Getter for the current UNIX time.
 *
 * @return an int representing the amount of seconds since the UNIX epoch
 */
size_t getUnixTime();

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

#ifdef WIN32
// Microsoft provides FUNCTION_s with more or less the same parameters.
// Notice that they are swapped when compared to POSIX FUNCTION_r.
struct tm* gmtime_r(time_t* t, struct tm* result);

struct tm* localtime_r(time_t* t, struct tm* result);
#endif
}
