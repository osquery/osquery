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
#include <string>

#ifdef WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <boost/optional.hpp>

#include <osquery/core.h>

namespace osquery {

#ifdef WIN32

/// Unfortunately, pid_t is not defined in Windows, however, DWORD is the
/// most appropriate alternative since process ID on Windows are stored in
/// a DWORD.
using pid_t = DWORD;
using PlatformPidType = HANDLE;
#else
using PlatformPidType = pid_t;
#endif

/// Constant for an invalid process
const PlatformPidType kInvalidPid = (PlatformPidType)-1;

/**
 * @brief Categories of process states adapted to be platform agnostic
 *
 * A process can have the following states. Unfortunately, because of operating
 * system differences. A generic state change is not directly translatable on
 * Windows. Therefore, PROCESS_STATE_CHANGE will only occur on POSIX systems.
 */
enum ProcessState {
  PROCESS_ERROR = -1,
  PROCESS_STILL_ALIVE = 0,
  PROCESS_EXITED,
  PROCESS_STATE_CHANGE
};

/**
 * @brief Platform-agnostic process object.
 *
 * PlatformProcess is a specialized, platform-agnostic class that handles the
 * process operation needs of osquery.
 */
class PlatformProcess : private boost::noncopyable {
 public:
  /// Default constructor marks the process as invalid
  explicit PlatformProcess() : id_(kInvalidPid) {}
  explicit PlatformProcess(PlatformPidType id);

  PlatformProcess(const PlatformProcess& src) = delete;
  PlatformProcess(PlatformProcess&& src) noexcept;
  ~PlatformProcess();

  PlatformProcess& operator=(const PlatformProcess& process) = delete;
  bool operator==(const PlatformProcess& process) const;
  bool operator!=(const PlatformProcess& process) const;

  /// Returns the associated process' process ID (on POSIX, pid() and
  /// nativeHandle() do not differ)
  int pid() const;

  /**
   * @brief Returns the native "handle" object of the process.
   *
   * On Windows, this is in the of a HANDLE. For POSIX, this is just the pid_t
   * of the process.
   */
  PlatformPidType nativeHandle() const { return id_; }

  /// Hard terminates the process
  bool kill() const;

  /// Returns whether the PlatformProcess object is valid
  bool isValid() const { return (id_ != kInvalidPid); }

  /// Returns the current process
  static std::shared_ptr<PlatformProcess> getCurrentProcess();

  /// Returns the launcher process (only works for worker processes)
  static std::shared_ptr<PlatformProcess> getLauncherProcess();

  /**
   * @brief Creates a new worker process.
   *
   * Launches a worker process given a worker executable path, number of
   * arguments, and an array of arguments. All double quotes within each entry
   * in the array of arguments will be supplanted with a preceding blackslash.
   */
  static std::shared_ptr<PlatformProcess> launchWorker(
      const std::string& exec_path, int argc, char** argv);

  /**
  * @brief Creates a new extension process.
  *
  * Launches a new extension with various options. Any double quotes in the
  * extension name will be stripped away.
  */
  static std::shared_ptr<PlatformProcess> launchExtension(
      const std::string& exec_path,
      const std::string& extension,
      const std::string& extensions_socket,
      const std::string& extensions_timeout,
      const std::string& extensions_interval,
      const std::string& verbose);

 private:
  /// "Handle" of the process. On Windows, this will be a HANDLE. On POSIX
  /// systems, this will be a pid_t.
  PlatformPidType id_;
};

/// Causes the current thread to sleep for a specified time in milliseconds
void sleepFor(unsigned int msec);

/// Set the enviroment variable name with value value
bool setEnvVar(const std::string& name, const std::string& value);

/// Unsets the environment variable specified by name
bool unsetEnvVar(const std::string& name);

/**
 * @brief Returns the value of the specified environment variable name
 *
 * If the environment variable does not exist, boost::none is returned.
 */
boost::optional<std::string> getEnvVar(const std::string& name);

/// Checks to see if the launcher process is dead (only works for worker
/// processes).
bool isLauncherProcessDead(PlatformProcess& launcher);

/// Non-blocking check on the state of a specificed child process.
ProcessState checkChildProcessStatus(const osquery::PlatformProcess& process,
                                     int& status);

/// Waits for defunct processes to terminate
void cleanupDefunctProcesses();

/// Sets the current process to run with background scheduling priority
void setToBackgroundPriority();
}
