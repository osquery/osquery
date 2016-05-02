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

namespace osquery {

PlatformProcess::PlatformProcess(PlatformPidType id) { 
  id_ = duplicateHandle(id);
}

PlatformProcess::PlatformProcess(const PlatformProcess& src) {
  id_ = duplicateHandle(src.nativeHandle());
}

PlatformProcess::PlatformProcess(PlatformProcess&& src) {
  id_ = src.id_;
  src.id_ = kInvalidPid;
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

bool PlatformProcess::kill() {
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
  std::stringstream args_stream;
  args_stream << "\"" << name << "\"";
  
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
  
  if (!::SetEnvironmentVariableA("OSQUERY_WORKER", "1") ||
      !::SetEnvironmentVariableA("OSQUERY_LAUNCHER", handle.c_str())) {
    ::CloseHandle(hLauncherProcess);

    return PlatformProcess(kInvalidPid);
  }
  
  std::string args = args_stream.str();
  std::vector<char> argv(args.begin(), args.end());
  argv.push_back('\0');
  
  BOOL status = ::CreateProcessA(exec_path.c_str(),
                                 &argv[0],
                                 NULL,
                                 NULL,
                                 TRUE,
                                 0,
                                 NULL,
                                 NULL,
                                 &si,
                                 &pi);
  ::SetEnvironmentVariableA("OSQUERY_WORKER", NULL);
  ::SetEnvironmentVariableA("OSQUERY_LAUNCHER", NULL);
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
  std::stringstream args_stream;
  args_stream << "\"osquery extension: " << extension << "\" ";
  args_stream << "--socket " << extensions_socket << " ";
  args_stream << "--timeout " << extensions_timeout << " ";
  args_stream << "--interval " << extensions_interval << " ";
  
  if (verbose == "true") {
    args_stream << "--verbose";
  }
  
  std::string args = args_stream.str();
  std::vector<char> argv(args.begin(), args.end());
  argv.push_back('\0');

  if (!::SetEnvironmentVariableA("OSQUERY_EXTENSIONS", "1")) {
    return PlatformProcess(kInvalidPid);
  }
  
  BOOL status = ::CreateProcessA(exec_path.c_str(),
                                 &argv[0],
                                 NULL,
                                 NULL,
                                 TRUE,
                                 0,
                                 NULL,
                                 NULL,
                                 &si,
                                 &pi);
  ::SetEnvironmentVariableA("OSQUERY_EXTENSIONS", NULL);
  
  if (!status) {
    return PlatformProcess(kInvalidPid);
  }

  PlatformProcess process(pi.hProcess);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  
  return process;
}

PlatformProcess PlatformProcess::fromPlatformPid(PlatformPidType id) {
  return PlatformProcess(id);
}
}

