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

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Suppressing unexpected token following preprocessor directive warning
#pragma warning(push, 3)
#pragma warning(disable : 4067)
#include <sddl.h>
#pragma warning(pop)
#endif

#include <osquery/core.h>
#include <osquery/system.h>

namespace osquery {

/// Constant for an invalid process
const auto kInvalidPid = (PlatformPidType)-1;

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

#ifdef WIN32
  /*
   * @brief Constructor that accepts a pid_t
   *
   * Allow for the creation of a PlatformProcess object from a pid_t. On
   * Windows, PlatformPidType is not a pid_t because it cannot be assumed that
   * the PID will point to the expected process. After a process dies, the PID
   * can be immediately reused. Using HANDLEs (as what is done now) mitigates
   * this issue.
   */
  explicit PlatformProcess(pid_t pid);
#endif

  PlatformProcess(const PlatformProcess& src) = delete;
  PlatformProcess(PlatformProcess&& src) noexcept;
  virtual ~PlatformProcess();

  PlatformProcess& operator=(const PlatformProcess& process) = delete;
  bool operator==(const PlatformProcess& process) const;
  bool operator!=(const PlatformProcess& process) const;

  /**
   * @brief Returns the process's ID
   *
   * Returns the associated process' process ID (on POSIX, pid() and
   * nativeHandle() do not differ).
   *
   * NOTE: In most situations, this should ideally not be used on Windows when
   * dealing when tracking process lifetimes.
   */
  int pid() const;

  /**
   * @brief Returns the native "handle" object of the process.
   *
   * On Windows, this is in the of a HANDLE. For POSIX, this is just the pid_t
   * of the process.
   */
  PlatformPidType nativeHandle() const {
    return id_;
  }

  /// Hard terminates the process
  bool kill() const;

  /**
   * @brief Attempt to kill a process gracefully, usually a child process.
   */
  bool killGracefully() const;

  /**
   * @brief Wait or cleanup a process, usually a child process.
   *
   * This will wait for a process to cleanup. Use this after requesting a
   * graceful shutdown.
   *
   * @return true if the process was cleaned, otherwise false.
   */
  bool cleanup() const;

  /// Returns whether the PlatformProcess object is valid
  bool isValid() const {
    return (id_ != kInvalidPid);
  }

  virtual ProcessState checkStatus(int& status) const;

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
      bool verbose = false);

  /**
   * @brief Launches a new test Python script.
   *
   * This will launch a new Python process to run the specified script and
   * script arguments. This is used within the test harnesses to run example
   * TLS server scripts.
   */
  static std::shared_ptr<PlatformProcess> launchTestPythonScript(
      const std::string& args);

 private:
  /**
   * @brief Stores the native handle denoting the process
   *
   * "Handle" of the process. On Windows, this will be a HANDLE. On POSIX
   * systems, this will be a pid_t.
   */
  PlatformPidType id_;
};

#ifdef WIN32
/**
 * @brief Handles the resource lifetime of a PSECURITY_DESCRIPTOR
 *
 * Class to handle the scope of a PSECURITY_DESCRIPTOR from
 * GetSecurityInfo/GetNamedSecurityInfo class of functions (or any
 * PSECURITY_DESCRIPTOR pointer where the buffer is allocated via LocalAlloc)
 */
class SecurityDescriptor {
 public:
  explicit SecurityDescriptor(PSECURITY_DESCRIPTOR sd) : sd_(sd) {}

  SecurityDescriptor(SecurityDescriptor&& src) noexcept {
    sd_ = src.sd_;
    std::swap(sd_, src.sd_);
  }

  ~SecurityDescriptor() {
    if (sd_ != nullptr) {
      ::LocalFree(sd_);
      sd_ = nullptr;
    }
  }

 private:
  PSECURITY_DESCRIPTOR sd_{nullptr};
};
#endif

/// Returns the current user's ID (UID on POSIX systems and RID for Windows)
int platformGetUid();

inline void sleepFor(size_t msec) {
  std::chrono::milliseconds mduration(msec);
  std::this_thread::sleep_for(mduration);
}

/// Set the enviroment variable name with value value.
bool setEnvVar(const std::string& name, const std::string& value);

/// Unsets the environment variable specified by name.
bool unsetEnvVar(const std::string& name);

/**
 * @brief Returns the value of the specified environment variable name.
 *
 * If the environment variable does not exist, boost::none is returned.
 */
boost::optional<std::string> getEnvVar(const std::string& name);

/**
 * @brief Returns a handle of the specified module path
 *
 * On POSIX, this invokes dlopen with RTLD_NOW and RTLD_LOCAL flags
 */
ModuleHandle platformModuleOpen(const std::string& path);

/**
 * @brief Returns a pointer of where the requested symbol exists
 */
void* platformModuleGetSymbol(ModuleHandle module, const std::string& symbol);

/**
 * @brief Returns a string of the last error
 *
 * On Windows, this returns the last error message which may not necessarily be
 * from a module operation. It is suggested to call this immediately after a
 * platformModule function for best accuracy.
 */
std::string platformModuleGetError();

/**
 * @brief Closes the library handle
 *
 * On Windows, this will also try to unload the library.
 */
bool platformModuleClose(ModuleHandle module);

/**
 * @brief Checks to see if the launcher process is dead
 *
 * Note, this only works on worker processes.
 */
bool isLauncherProcessDead(PlatformProcess& launcher);

/// Sets the current process to run with background scheduling priority.
void setToBackgroundPriority();

/**
* @brief Returns the current processes pid
*
* On Windows, returns the value of GetCurrentProcessId
* and on posix platforms returns getpid()
*/
int platformGetPid();

/**
* @brief Returns the current thread id
*
* On Windows, returns the value of GetCurrentThreadId
* and on posix platforms returns gettid()
*/
int platformGetTid();
} // namespace osquery
