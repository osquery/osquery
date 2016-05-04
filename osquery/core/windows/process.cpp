/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <sstream>
#include <signal.h>
#include <sys/types.h>

#include "osquery/core/process.h"

extern char **environ;

namespace {
osquery::PlatformPidType __declspec(nothrow) duplicateHandle(osquery::PlatformPidType src) {
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
}

namespace osquery {

PlatformProcess::PlatformProcess(PlatformPidType id) { 
  id_ = duplicateHandle(id);
}

PlatformProcess::PlatformProcess(const PlatformProcess& src) {
  id_ = duplicateHandle(src.nativeHandle());
}

PlatformProcess::PlatformProcess(PlatformProcess&& src) {
  id_ = kInvalidPid;
  std::swap(id_, src.id_);
}  

PlatformProcess::~PlatformProcess() { 
  if (id_ != kInvalidPid) {
    ::CloseHandle(id_);
    id_ = kInvalidPid;
  }
}

PlatformProcess& PlatformProcess::operator=(const PlatformProcess& process) {
  id_ = duplicateHandle(process.nativeHandle());
  return *this;
}

bool PlatformProcess::operator==(const PlatformProcess& process) const {
  return (::GetProcessId(nativeHandle()) == ::GetProcessId(process.nativeHandle()));
}

bool PlatformProcess::operator!=(const PlatformProcess& process) const {
  return (::GetProcessId(nativeHandle()) != ::GetProcessId(process.nativeHandle()));
}

int PlatformProcess::pid() const {
  return ::GetProcessId(id_);
}

bool PlatformProcess::kill() const {
  if (id_ == kInvalidPid) {
    return false;
  }
  
  return ::TerminateProcess(id_, 0);
}

PlatformProcess PlatformProcess::launchWorker(const std::string& exec_path, const std::string& name) {
  ::STARTUPINFOA si = { 0 };
  ::PROCESS_INFORMATION pi = { 0 };
  
  si.cb = sizeof(si);
  
  // TODO(#1991): We currently do not sanitize or check for bad characters in for the worker name. Names
  //              with double quotes have the potential of causing argument parsing issues. However, it
  //              is not a huge concern for the worker process, for it does not pass any command line 
  //              arguments.
  std::stringstream argv_stream;
  argv_stream << "\"" << name << "\"";
  
  std::stringstream handle_stream;
  
  // TODO(#1991): The HANDLE exposed to the child process only has SYNCHRONIZE and 
  //              PROCESS_QUERY_LIMITED_INFORMATION privileges which is enough to cover the current use 
  //              cases. This may not be the case in the future...
  HANDLE hLauncherProcess = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 
                                          TRUE, 
                                          GetCurrentProcessId());
  if (hLauncherProcess == NULL) {
    return PlatformProcess(kInvalidPid);
  }
  
  handle_stream << hLauncherProcess;
  std::string handle = handle_stream.str();
  
  // In the POSIX version, the environment variable OSQUERY_WORKER is set to the string form of the
  // child process' process ID. However, this is not easily doable on Windows. Since the value does
  // not appear to be used by the rest of osquery, we currently just set it to '1'.
  //
  // For the worker case, we also set another environment variable, OSQUERY_LAUNCHER. OSQUERY_LAUNCHER
  // stores the string form of a HANDLE to the current process. This is mostly used for detecting the 
  // death of the launcher process in WatcherWatcherRunner::start
  if (!setEnvVar("OSQUERY_WORKER", "1") ||
      !setEnvVar("OSQUERY_LAUNCHER", handle.c_str())) {
    ::CloseHandle(hLauncherProcess);

    return PlatformProcess(kInvalidPid);
  }
  
  // We don't directly use argv.c_str() as the value for lpCommandLine in CreateProcess since
  // that argument requires a modifiable buffer. So, instead, we off-load the contents of argv
  // into a vector which will have its backing memory as modifiable.
  std::string argv = argv_stream.str();
  std::vector<char> mutable_argv(argv.begin(), argv.end());
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
    return PlatformProcess(kInvalidPid);
  }
  
  PlatformProcess process(pi.hProcess);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  
  return process;
}

PlatformProcess PlatformProcess::launchExtension(const std::string& exec_path, 
                                                 const std::string& extension, 
                                                 const std::string& extensions_socket,
                                                 const std::string& extensions_timeout,
                                                 const std::string& extensions_interval,
                                                 const std::string& verbose) {
  ::STARTUPINFOA si = { 0 };
  ::PROCESS_INFORMATION pi = { 0 };
  
  si.cb = sizeof(si);
  
  // TODO(#1991): extension name should be sanitized or checked for invalid characters such as 
  //              double quotes. An extension name with bad characters has the potential of affecting
  //              command line argument parsing in the extension process which may lead to a dysfunctional
  //              extension.
  std::stringstream argv_stream;
  argv_stream << "\"osquery extension: " << extension << "\" ";
  argv_stream << "--socket " << extensions_socket << " ";
  argv_stream << "--timeout " << extensions_timeout << " ";
  argv_stream << "--interval " << extensions_interval << " ";
  
  if (verbose == "true") {
    argv_stream << "--verbose";
  }

  // We don't directly use argv.c_str() as the value for lpCommandLine in CreateProcess since
  // that argument requires a modifiable buffer. So, instead, we off-load the contents of argv
  // into a vector which will have its backing memory as modifiable.
  std::string argv = argv_stream.str();
  std::vector<char> mutable_argv(argv.begin(), argv.end());
  mutable_argv.push_back('\0');

  // In POSIX, this environment variable is set to the child's process ID. But that is not easily
  // accomplishable on Windows and provides no value since this is never used elsewhere in the core.
  if (!setEnvVar("OSQUERY_EXTENSION", "1")) {
    return PlatformProcess(kInvalidPid);
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
    return PlatformProcess(kInvalidPid);
  }

  PlatformProcess process(pi.hProcess);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  
  return process;
}
}

