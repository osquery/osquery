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

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/status.h>

// clang-format off
#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif
#define STR_EX(x) x
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_case_name, test_name) \
  friend class test_case_name##_##test_name##_Test
#endif
// clang-format on

#ifndef __constructor__
#define __registry_constructor__ __attribute__((constructor(101)))
#define __plugin_constructor__ __attribute__((constructor(102)))
#else
#define __registry_constructor__ __attribute__((__constructor__(101)))
#define __plugin_constructor__ __attribute__((__constructor__(102)))
#endif

/// A configuration error is catastrophic and should exit the watcher.
#define EXIT_CATASTROPHIC 78

namespace osquery {

/// The version of osquery, includes the git revision if not tagged.
extern const std::string kVersion;

/// The SDK version removes any git revision hash (1.6.1-g0000 becomes 1.6.1).
extern const std::string kSDKVersion;

/// Identifies the build platform of either the core extension.
extern const std::string kSDKPlatform;

/// Use a macro for the sdk/platform literal, symbols available in lib.cpp.
#define OSQUERY_SDK_VERSION STR(OSQUERY_BUILD_SDK_VERSION)
#define OSQUERY_PLATFORM STR(OSQUERY_BUILD_PLATFORM)

/**
 * @brief A helpful tool type to report when logging, print help, or debugging.
 */
enum ToolType {
  OSQUERY_TOOL_UNKNOWN = 0,
  OSQUERY_TOOL_SHELL,
  OSQUERY_TOOL_DAEMON,
  OSQUERY_TOOL_TEST,
  OSQUERY_EXTENSION,
};

/// Helper alias for defining mutexes throughout the codebase.
using Mutex = std::mutex;

/// Helper alias for write locking a mutex.
using WriteLock = std::lock_guard<Mutex>;

/// Helper alias for read locking a mutex (do not support a ReadMutex).
// using ReadLock = std::shared_lock<std::shared_mutex>;

/// The osquery tool type for runtime decisions.
extern ToolType kToolType;

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
  Initializer(int& argc, char**& argv, ToolType tool = OSQUERY_TOOL_TEST);

  /**
   * @brief Sets up the process as an osquery daemon.
   *
   * A daemon has additional constraints, it can use a process mutex, check
   * for sane/non-default configurations, etc.
   */
  void initDaemon() const;

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

  /// Turns off various aspects of osquery such as event loops.
  void shutdown() const;

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

 private:
  /// Initialize this process as an osquery daemon worker.
  void initWorker(const std::string& name) const;

  /// Initialize the osquery watcher, optionally spawn a worker.
  void initWatcher() const;

  /// Set and wait for an active plugin optionally broadcasted.
  void initActivePlugin(const std::string& type, const std::string& name) const;

 private:
  int* argc_{nullptr};
  char*** argv_{nullptr};
  ToolType tool_;
  std::string binary_;
};

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
 * @brief Getter for the current time, in a human-readable format.
 *
 * @return the current date/time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string getAsciiTime();

/**
 * @brief Getter for the current UNIX time.
 *
 * @return an int representing the amount of seconds since the UNIX epoch
 */
size_t getUnixTime();

/**
 * @brief Create a pid file
 *
 * @return A status object indicating the success or failure of the operation
 */
Status createPidFile();

/**
 * @brief Forcefully request the application stop.
 *
 * Since all osquery tools may implement various 'dispatched' services in the
 * form of event handler threads or thrift service and client pools, a stop
 * request should behave nicely and request these services stop.
 *
 * Use shutdown whenever you would normally call ::exit.
 */
void shutdown(int recode, bool wait = false);

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

  /// Check if effective privileges do not match real.
  bool dropped() { return (getuid() != geteuid() || getgid() != getegid()); }

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

  /// If this was a filesystem-prompted privilege drop.
  bool fs_drop_{false};

  /// Store times for restoration if requested.
  struct timespec atime;
  struct timespec mtime;

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
}
