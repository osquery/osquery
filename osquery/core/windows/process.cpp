/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <vector>

#include <signal.h>

#include <sys/types.h>

#include <boost/algorithm/string.hpp>

#include "osquery/core/process.h"

namespace osquery {

static PlatformPidType __declspec(nothrow)
    duplicateHandle(osquery::PlatformPidType src) {
  osquery::PlatformPidType handle = osquery::kInvalidPid;

  if (src != osquery::kInvalidPid) {
    if (!::DuplicateHandle(GetCurrentProcess(),
                           src,
                           GetCurrentProcess(),
                           &handle,
                           0,
                           FALSE,
                           DUPLICATE_SAME_ACCESS)) {
      handle = osquery::kInvalidPid;
    }
  }
  return handle;
}

PlatformProcess::PlatformProcess(PlatformPidType id) {
  id_ = duplicateHandle(id);
}

PlatformProcess::PlatformProcess(PlatformProcess &&src) {
  id_ = kInvalidPid;
  std::swap(id_, src.id_);
}

PlatformProcess::~PlatformProcess() {
  if (id_ != kInvalidPid) {
    ::CloseHandle(id_);
    id_ = kInvalidPid;
  }
}

bool PlatformProcess::operator==(const PlatformProcess &process) const {
  return (::GetProcessId(nativeHandle()) ==
          ::GetProcessId(process.nativeHandle()));
}

bool PlatformProcess::operator!=(const PlatformProcess &process) const {
  return (::GetProcessId(nativeHandle()) !=
          ::GetProcessId(process.nativeHandle()));
}

int PlatformProcess::pid() const { return (int)::GetProcessId(id_); }

bool PlatformProcess::kill() const {
  if (id_ == kInvalidPid) {
    return false;
  }

  return (::TerminateProcess(id_, 0) != FALSE);
}

std::shared_ptr<PlatformProcess> PlatformProcess::getCurrentProcess() {
  HANDLE handle =
      ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
  if (handle == NULL) {
    return std::make_shared<PlatformProcess>();
  }

  return std::make_shared<PlatformProcess>(handle);
}

std::shared_ptr<PlatformProcess> PlatformProcess::getLauncherProcess() {
  auto launcher_handle = getEnvVar("OSQUERY_LAUNCHER");
  if (!launcher_handle) {
    return std::make_shared<PlatformProcess>();
  }

  // Convert the environment variable into a HANDLE (the value from environment
  // variable should be a hex value). As a precaution, ensure that the HANDLE is
  // valid.
  HANDLE handle = INVALID_HANDLE_VALUE;

  try {
    handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(
        std::stoull(*launcher_handle, nullptr, 16)));
  }
  catch (std::invalid_argument e) {
    return std::make_shared<PlatformProcess>();
  }
  catch (std::out_of_range e) {
    return std::make_shared<PlatformProcess>();
  }

  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    return std::make_shared<PlatformProcess>();
  }

  return std::make_shared<PlatformProcess>(handle);
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchWorker(
    const std::string &exec_path, int argc, char **argv) {
  ::STARTUPINFOA si = {0};
  ::PROCESS_INFORMATION pi = {0};

  si.cb = sizeof(si);

  std::stringstream argv_stream;
  std::stringstream handle_stream;

  // The HANDLE exposed to the child process is currently limited to only having
  // SYNCHRONIZE and PROCESS_QUERY_LIMITED_INFORMATION capabilities. The
  // SYNCHRONIZE permissions allows for WaitForSingleObject.
  // PROCESS_QUERY_LIMITED_INFORMATION allows for the ability to use the
  // GetProcessId and GetExitCodeProcess API functions.
  HANDLE hLauncherProcess =
      ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    TRUE,
                    GetCurrentProcessId());
  if (hLauncherProcess == NULL) {
    return std::shared_ptr<PlatformProcess>();
  }

  handle_stream << hLauncherProcess;
  std::string handle = handle_stream.str();

  // In the POSIX version, the environment variable OSQUERY_WORKER is set to the
  // string form of the child process' process ID. However, this is not easily
  // doable on Windows. Since the value does not appear to be used by the rest
  // of osquery, we currently just set it to '1'.
  //
  // For the worker case, we also set another environment variable,
  // OSQUERY_LAUNCHER. OSQUERY_LAUNCHER stores the string form of a HANDLE to
  // the current process. This is mostly used for detecting the death of the
  // launcher process in WatcherWatcherRunner::start
  if (!setEnvVar("OSQUERY_WORKER", "1") ||
      !setEnvVar("OSQUERY_LAUNCHER", handle.c_str())) {
    ::CloseHandle(hLauncherProcess);

    return std::shared_ptr<PlatformProcess>();
  }

  // Since Windows does not accept a char * array for arguments, we have to
  // build one as a string. Therefore, we need to make sure that special
  // characters are not present that would obstruct the parsing of arguments.
  // For now, we strip out all double quotes. If the an entry in argv has
  // spaces, we will put double-quotes around the entry.
  //
  // NOTE: This is extremely naive and will break the moment complexities are
  //       involved... Windows command line argument parsing is extremely
  //       nitpicky and is different in behavior than POSIX argv parsing.
  //
  // We don't directly use argv.c_str() as the value for lpCommandLine in
  // CreateProcess since that argument requires a modifiable buffer. So,
  // instead, we off-load the contents of argv into a vector which will have its
  // backing memory as modifiable.
  for (size_t i = 0; i < argc; i++) {
    std::string component(argv[i]);
    if (component.find(" ") != std::string::npos) {
      boost::replace_all(component, "\"", "\\\"");
      argv_stream << "\"" << component << "\" ";
    } else {
      argv_stream << component << " ";
    }
  }

  std::string cmdline = argv_stream.str();
  std::vector<char> mutable_argv(cmdline.begin(), cmdline.end());
  mutable_argv.push_back('\0');

  BOOL status = ::CreateProcessA(exec_path.c_str(),
                                 &mutable_argv[0],
                                 NULL,
                                 NULL,
                                 TRUE,
                                 0,
                                 NULL,
                                 NULL,
                                 &si,
                                 &pi);
  unsetEnvVar("OSQUERY_WORKER");
  unsetEnvVar("OSQUERY_LAUNCHER");
  ::CloseHandle(hLauncherProcess);

  if (!status) {
    return std::shared_ptr<PlatformProcess>();
  }

  auto process = std::make_shared<PlatformProcess>(pi.hProcess);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);

  return process;
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchExtension(
    const std::string &exec_path,
    const std::string &extension,
    const std::string &extensions_socket,
    const std::string &extensions_timeout,
    const std::string &extensions_interval,
    const std::string &verbose) {
  ::STARTUPINFOA si = {0};
  ::PROCESS_INFORMATION pi = {0};

  si.cb = sizeof(si);

  // To prevent errant double quotes from altering the intended arguments for
  // argv, we strip them out completely.
  std::stringstream argv_stream;
  argv_stream << "\"osquery extension: "
              << boost::replace_all_copy(extension, "\"", "") << "\" ";
  argv_stream << "--socket \"" << extensions_socket << "\" ";
  argv_stream << "--timeout " << extensions_timeout << " ";
  argv_stream << "--interval " << extensions_interval << " ";

  if (verbose == "true") {
    argv_stream << "--verbose";
  }

  // We don't directly use argv.c_str() as the value for lpCommandLine in
  // CreateProcess since that argument requires a modifiable buffer. So,
  // instead, we off-load the contents of argv into a vector which will have its
  // backing memory as modifiable.
  std::string argv = argv_stream.str();
  std::vector<char> mutable_argv(argv.begin(), argv.end());
  mutable_argv.push_back('\0');

  // In POSIX, this environment variable is set to the child's process ID. But
  // that is not easily accomplishable on Windows and provides no value since
  // this is never used elsewhere in the core.
  if (!setEnvVar("OSQUERY_EXTENSION", "1")) {
    return std::shared_ptr<PlatformProcess>();
  }

  BOOL status = ::CreateProcessA(exec_path.c_str(),
                                 &mutable_argv[0],
                                 NULL,
                                 NULL,
                                 TRUE,
                                 0,
                                 NULL,
                                 NULL,
                                 &si,
                                 &pi);
  unsetEnvVar("OSQUERY_EXTENSION");

  if (!status) {
    return std::shared_ptr<PlatformProcess>();
  }

  auto process = std::make_shared<PlatformProcess>(pi.hProcess);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);

  return process;
}
}

