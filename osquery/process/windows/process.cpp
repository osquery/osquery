/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>
#include <vector>

#include <signal.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <osquery/process/process.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace fs = boost::filesystem;

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
  id_ = src.id_;
  src.id_ = kInvalidPid;
}

PlatformProcess::~PlatformProcess() {
  if (isValid()) {
    ::CloseHandle(id_);
    id_ = kInvalidPid;
  }
}

PlatformProcess& PlatformProcess::operator=(
    PlatformProcess&& process) noexcept {
  id_ = process.id_;
  process.id_ = kInvalidPid;
  return *this;
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
  auto pid = (id_ == INVALID_HANDLE_VALUE) ? -1 : GetProcessId(id_);
  return static_cast<int>(pid);
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

void PlatformProcess::warnResourceLimitHit() const {
  // Not implemented
}

ProcessState PlatformProcess::checkStatus(int& status) const {
  unsigned long exit_code = 0;
  if (!isValid()) { // see issue #7324
    return PROCESS_ERROR;
  }

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
  auto res = std::make_shared<PlatformProcess>(handle);
  CloseHandle(handle);
  return res;
}

int PlatformProcess::getCurrentPid() {
  return PlatformProcess::getCurrentProcess()->pid();
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
  } catch (const std::invalid_argument& /* e */) {
    return std::make_shared<PlatformProcess>();
  } catch (const std::out_of_range& /* e */) {
    return std::make_shared<PlatformProcess>();
  }

  if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
    return std::make_shared<PlatformProcess>();
  }

  return std::make_shared<PlatformProcess>(handle);
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchWorker(
    const std::string& exec_path, int argc, char** argv) {
  ::STARTUPINFO si = {0};
  ::PROCESS_INFORMATION pi = {nullptr};

  si.cb = sizeof(si);

  std::wstringstream argv_stream;
  std::wstringstream handle_stream;

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
    std::wstring component(stringToWstring(argv[i]));
    if (component.find(' ') != std::string::npos) {
      boost::replace_all(component, L"\"", L"\\\"");
      argv_stream << L"\"" << component << L"\" ";
    } else {
      argv_stream << component << L" ";
    }
  }

  auto cmdline = argv_stream.str();
  std::vector<WCHAR> mutable_argv(cmdline.begin(), cmdline.end());
  mutable_argv.push_back(L'\0');

  LPWCH retrievedEnvironment = GetEnvironmentStrings();
  LPCWSTR currentEnvironment = retrievedEnvironment;
  std::wstringstream childEnvironment;
  while (*currentEnvironment) {
    childEnvironment << currentEnvironment;
    childEnvironment << L'\0';
    currentEnvironment += lstrlen(currentEnvironment) + 1;
  }

  FreeEnvironmentStrings(retrievedEnvironment);

  // In the POSIX version, the environment variable OSQUERY_WORKER is set to the
  // string form of the child process' process ID. However, this is not easily
  // doable on Windows. Since the value does not appear to be used by the rest
  // of osquery, we currently just set it to '1'.
  //
  // For the worker case, we also set another environment variable,
  // OSQUERY_LAUNCHER. OSQUERY_LAUNCHER stores the string form of a HANDLE to
  // the current process. This is mostly used for detecting the death of the
  // launcher process in WatcherWatcherRunner::start
  childEnvironment << L"OSQUERY_WORKER=1" << L'\0';
  childEnvironment << L"OSQUERY_LAUNCHER=" << handle << L'\0' << L'\0';

  std::wstring environmentString = childEnvironment.str();

  auto status =
      ::CreateProcess(nullptr,
                      mutable_argv.data(),
                      nullptr,
                      nullptr,
                      TRUE,
                      CREATE_UNICODE_ENVIRONMENT | IDLE_PRIORITY_CLASS,
                      &environmentString[0],
                      nullptr,
                      &si,
                      &pi);
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
    const std::string& extensions_socket,
    const std::string& extensions_timeout,
    const std::string& extensions_interval,
    bool verbose) {
  ::STARTUPINFO si = {0};
  ::PROCESS_INFORMATION pi = {nullptr};

  si.cb = sizeof(si);

  std::wstring const wexec_path = stringToWstring(exec_path);

  // To prevent errant double quotes from altering the intended arguments for
  // argv, we strip them out completely.
  std::wstringstream argv_stream;
  argv_stream << L"\"" << boost::replace_all_copy(wexec_path, L"\"", L"")
              << L"\" ";
  if (verbose) {
    argv_stream << L"--verbose ";
  }
  argv_stream << L"--socket \"" << stringToWstring(extensions_socket) << L"\" ";
  argv_stream << L"--timeout " << stringToWstring(extensions_timeout) << L" ";
  argv_stream << L"--interval " << stringToWstring(extensions_interval) << L" ";

  // We don't directly use argv.c_str() as the value for lpCommandLine in
  // CreateProcess since that argument requires a modifiable buffer. So,
  // instead, we off-load the contents of argv into a vector which will have its
  // backing memory as modifiable.
  auto argv = argv_stream.str();
  std::vector<WCHAR> mutable_argv(argv.begin(), argv.end());
  mutable_argv.push_back(L'\0');

  // In POSIX, this environment variable is set to the child's process ID. But
  // that is not easily accomplishable on Windows and provides no value since
  // this is never used elsewhere in the core.
  if (!setEnvVar("OSQUERY_EXTENSION", "1")) {
    return std::shared_ptr<PlatformProcess>();
  }

  auto ext_path = fs::path(wexec_path);

  // We are autoloading a Python extension, so pass off to our helper
  if (ext_path.extension().wstring() == L".ext") {
    return launchTestPythonScript(wstringToString(
        std::wstring(mutable_argv.begin(), mutable_argv.end())));
  } else {
    auto status =
        ::CreateProcess(nullptr,
                        mutable_argv.data(),
                        nullptr,
                        nullptr,
                        TRUE,
                        CREATE_UNICODE_ENVIRONMENT | IDLE_PRIORITY_CLASS,
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
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchTestPythonScript(
    const std::string& args) {
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {nullptr};

  auto argv = L"python " + stringToWstring(args);
  std::vector<WCHAR> mutable_argv(argv.begin(), argv.end());
  mutable_argv.push_back(L'\0');
  si.cb = sizeof(si);

  const auto pythonEnv = getEnvVar("OSQUERY_PYTHON_INTERPRETER_PATH");
  if (!pythonEnv.is_initialized()) {
    return nullptr;
  }

  auto pythonPath = *pythonEnv;

  std::shared_ptr<PlatformProcess> process;
  if (::CreateProcessW(stringToWstring(pythonPath).c_str(),
                       mutable_argv.data(),
                       nullptr,
                       nullptr,
                       FALSE,
                       IDLE_PRIORITY_CLASS,
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
} // namespace osquery
