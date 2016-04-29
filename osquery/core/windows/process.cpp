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

namespace osquery 
{

PlatformProcess::PlatformProcess(PlatformPidType id) : id_(id) 
{ 
  PlatformPidType handle = kInvalidPid;
  if (!::DuplicateHandle(GetCurrentProcess(), 
                         id, 
                         GetCurrentProcess(),
                         &handle,
                         0,
                         FALSE,
                         DUPLICATE_SAME_ACCESS)) {
    id_ = kInvalidPid;
  } else {
    id_ = handle;
  }
}

PlatformProcess::~PlatformProcess()
{ 
  if (id_ != kInvalidPid) {
    ::CloseHandle(id_);
  }
  id_ = kInvalidPid;
}

bool PlatformProcess::kill()
{
  return ::TerminateProcess(id_, 0);
}

PlatformProcess PlatformProcess::launchWorker(const std::string& exec_path, const std::string& name)
{
  ::STARTUPINFOA si = { 0 };
  ::PROCESS_INFORMATION pi = { 0 };
  
  si.cb = sizeof(si);
  
  // XXX TODO XXX: We need to make that name does not contain any shell restricted characters.
  std::stringstream args_stream;
  args_stream << "\"" << name << "\"";
  
  std::stringstream handle_stream;
  
  HANDLE hLauncherProcess = ::OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId());
  if (hLauncherProcess == NULL) {
    // Failed to obtain HANDLE for current process
    
    // TODO: return a special error message?
    return PlatformProcess(kInvalidPid);
  }
  
  handle_stream << hLauncherProcess;
  std::string handle = handle_stream.str();
  
  if (!::SetEnvironmentVariableA("OSQUERY_WORKER", "1") ||
      !::SetEnvironmentVariableA("OSQUERY_LAUNCHER", handle.c_str())) {
    // Failed to set a crucial environment variable
    ::CloseHandle(hLauncherProcess);
    
    // TODO: how do we differentiate error levels?
    return PlatformProcess(kInvalidPid);
  }
  
  std::string args = args_stream.str();
  std::vector<char> argv(args.begin(), args.end());
  
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
    // Failed to create a new process
    
    // TODO: how do we differentiate error messages and provide debugging feedback?
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
                                                 const std::string& verbose)
{
  ::STARTUPINFOA si = { 0 };
  ::PROCESS_INFORMATION pi = { 0 };
  
  si.cb = sizeof(si);
  
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
    // Failed to set important environment variable
    
    // TODO: differentiate error message
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
    // Failed to create process
    
    // TODO: differentiate error message
    return PlatformProcess(kInvalidPid);
  }

  PlatformProcess process(pi.hProcess);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  
  return process;
}

PlatformProcess PlatformProcess::fromPlatformPid(PlatformPidType id)
{
  return PlatformProcess(id);
}

}

