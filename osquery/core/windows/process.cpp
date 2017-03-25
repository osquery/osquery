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

#include <boost/algorithm/string.hpp>

#include "osquery/core/process.h"

namespace osquery {

static PlatformPidType __declspec(nothrow)
    duplicateHandle(osquery::PlatformPidType src) {
  auto handle = osquery::kInvalidPid;

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

PlatformProcess::PlatformProcess(pid_t pid) {
  id_ = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (id_ == nullptr) {
    id_ = kInvalidPid;
  }
}

PlatformProcess::PlatformProcess(PlatformProcess&& src) noexcept {
  id_ = kInvalidPid;
  std::swap(id_, src.id_);
}

PlatformProcess::~PlatformProcess() {
  if (isValid()) {
    ::CloseHandle(id_);
    id_ = kInvalidPid;
  }
}

bool PlatformProcess::operator==(const PlatformProcess& process) const {
  return (::GetProcessId(nativeHandle()) ==
          ::GetProcessId(process.nativeHandle()));
}

bool PlatformProcess::operator!=(const PlatformProcess& process) const {
  return (::GetProcessId(nativeHandle()) !=
          ::GetProcessId(process.nativeHandle()));
}

int PlatformProcess::pid() const {
  return static_cast<int>(::GetProcessId(id_));
}

bool PlatformProcess::kill() const {
  if (!isValid()) {
    return false;
  }

  return (::TerminateProcess(nativeHandle(), 0) != FALSE);
}

bool PlatformProcess::killGracefully() const {
  return kill();
}

ProcessState PlatformProcess::checkStatus(int& status) const {
  unsigned long exit_code = 0;
  if (!::GetExitCodeProcess(nativeHandle(), &exit_code)) {
    unsigned long last_error = GetLastError();
    if (last_error == ERROR_WAIT_NO_CHILDREN) {
      return PROCESS_EXITED;
    }
    return PROCESS_ERROR;
  }

  if (exit_code == STILL_ACTIVE) {
    return PROCESS_STILL_ALIVE;
  }

  status = exit_code;
  return PROCESS_EXITED;
}

std::shared_ptr<PlatformProcess> PlatformProcess::getCurrentProcess() {
  auto handle =
      ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
  if (handle == nullptr) {
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
  auto handle = INVALID_HANDLE_VALUE;

  try {
    handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(
        std::stoull(*launcher_handle, nullptr, 16)));
  } catch (std::invalid_argument e) {
    return std::make_shared<PlatformProcess>();
  } catch (std::out_of_range e) {
    return std::make_shared<PlatformProcess>();
  }

  if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
    return std::make_shared<PlatformProcess>();
  }

  return std::make_shared<PlatformProcess>(handle);
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchWorker(
    const std::string& exec_path, int argc, char** argv) {
  ::STARTUPINFOA si = {0};
  ::PROCESS_INFORMATION pi = {nullptr};

  si.cb = sizeof(si);

  std::stringstream argv_stream;
  std::stringstream handle_stream;

  // The HANDLE exposed to the child process is currently limited to only having
  // SYNCHRONIZE and PROCESS_QUERY_LIMITED_INFORMATION capabilities. The
  // SYNCHRONIZE permissions allows for WaitForSingleObject.
  // PROCESS_QUERY_LIMITED_INFORMATION allows for the ability to use the
  // GetProcessId and GetExitCodeProcess API functions.
  auto hLauncherProcess =
      ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    TRUE,
                    GetCurrentProcessId());
  if (hLauncherProcess == nullptr) {
    return std::shared_ptr<PlatformProcess>();
  }

  handle_stream << hLauncherProcess;
  auto handle = handle_stream.str();

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
      !setEnvVar("OSQUERY_LAUNCHER", handle)) {
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

  auto cmdline = argv_stream.str();
  std::vector<char> mutable_argv(cmdline.begin(), cmdline.end());
  mutable_argv.push_back('\0');

  auto status = ::CreateProcessA(exec_path.c_str(),
                                 mutable_argv.data(),
                                 nullptr,
                                 nullptr,
                                 TRUE,
                                 0,
                                 nullptr,
                                 nullptr,
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
    const std::string& exec_path,
    const std::string& extension,
    const std::string& extensions_socket,
    const std::string& extensions_timeout,
    const std::string& extensions_interval,
    bool verbose) {
  ::STARTUPINFOA si = {0};
  ::PROCESS_INFORMATION pi = {nullptr};

  si.cb = sizeof(si);

  // To prevent errant double quotes from altering the intended arguments for
  // argv, we strip them out completely.
  std::stringstream argv_stream;
  argv_stream << "\"osquery extension: "
              << boost::replace_all_copy(extension, "\"", "") << "\" ";
  argv_stream << ((verbose) ? "--verbose" : "--noverbose") << " ";
  argv_stream << "--socket \"" << extensions_socket << "\" ";
  argv_stream << "--timeout " << extensions_timeout << " ";
  argv_stream << "--interval " << extensions_interval << " ";

  // We don't directly use argv.c_str() as the value for lpCommandLine in
  // CreateProcess since that argument requires a modifiable buffer. So,
  // instead, we off-load the contents of argv into a vector which will have its
  // backing memory as modifiable.
  auto argv = argv_stream.str();
  std::vector<char> mutable_argv(argv.begin(), argv.end());
  mutable_argv.push_back('\0');

  // In POSIX, this environment variable is set to the child's process ID. But
  // that is not easily accomplishable on Windows and provides no value since
  // this is never used elsewhere in the core.
  if (!setEnvVar("OSQUERY_EXTENSION", "1")) {
    return std::shared_ptr<PlatformProcess>();
  }

  auto status = ::CreateProcessA(exec_path.c_str(),
                                 mutable_argv.data(),
                                 nullptr,
                                 nullptr,
                                 TRUE,
                                 0,
                                 nullptr,
                                 nullptr,
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

std::shared_ptr<PlatformProcess> PlatformProcess::launchPythonScript(
    const std::string& args) {
  std::shared_ptr<PlatformProcess> process;

  STARTUPINFOA si = {0};
  PROCESS_INFORMATION pi = {nullptr};

  auto argv = "python " + args;
  std::vector<char> mutable_argv(argv.begin(), argv.end());
  mutable_argv.push_back('\0');
  si.cb = sizeof(si);

  auto pythonEnv = getEnvVar("OSQUERY_PYTHON_PATH");
  std::string pythonPath("");
  if (pythonEnv.is_initialized()) {
    pythonPath = *pythonEnv;
  }

  // Python is installed at this location if the provisioning script is used.
  // This path should work regardless of the existence of the SystemDrive
  // environment variable.
  pythonPath += "\\python.exe";

  if (::CreateProcessA(pythonPath.c_str(),
                       mutable_argv.data(),
                       nullptr,
                       nullptr,
                       FALSE,
                       0,
                       nullptr,
                       nullptr,
                       &si,
                       &pi)) {
    process.reset(new PlatformProcess(pi.hProcess));
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
  }

  return process;
}
}
