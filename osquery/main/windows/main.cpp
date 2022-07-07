/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

// These headers must be included in this order
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on

#include <osquery/core/core.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/main/main.h>
#include <osquery/process/process.h>
#include <osquery/core/system.h>
#include <osquery/utils/config/default_paths.h>
#include <osquery/utils/system/system.h>
#include <osquery/core/shutdown.h>
#include <osquery/filesystem/filesystem.h>

DECLARE_string(flagfile);

namespace osquery {

static const std::string kDefaultFlagsFile{OSQUERY_HOME "osquery.flags"};
static const std::string kServiceName{"osqueryd"};
static const std::string kServiceDisplayName{"osquery daemon service"};

static SERVICE_STATUS_HANDLE kStatusHandle = nullptr;
static SERVICE_STATUS kServiceStatus = {0};

const unsigned long kServiceShutdownWait{100};

/// Logging for when we need to debug this service
#define SLOG(s) ::osquery::DebugPrintf(s)

void DebugPrintf(const std::string& s) {
  auto dbgString = "[osqueryd] " + s;
  if (IsDebuggerPresent()) {
    ::OutputDebugStringA(dbgString.c_str());
  }
  LOG(ERROR) << s;
}

static void UpdateServiceStatus(unsigned long controls,
                                unsigned long state,
                                unsigned long exit_code,
                                unsigned long checkpoint,
                                unsigned long wait_hint = 0) {
  kServiceStatus.dwControlsAccepted = controls;
  kServiceStatus.dwCurrentState = state;
  kServiceStatus.dwWin32ExitCode = exit_code;
  kServiceStatus.dwCheckPoint = checkpoint;
  kServiceStatus.dwWaitHint = wait_hint;

  if (!::SetServiceStatus(kStatusHandle, &kServiceStatus)) {
    auto le = GetLastError();
    SLOG("SetServiceStatus failed (lasterror=" + std::to_string(le) + ")");
  }
}

/*
 * Parses arguments for the Windows service. Arguments to the Windows service
 * can be passed in two ways: via sc.exe (manual start) or via binPath
 * (automated start). Unfortunately, both use different methods of getting the
 * command line arguments. Manual start uses the argc and argv provided by
 * ServiceMain whereas automated start requires manual parsing of
 * GetCommandLine()
 */
class ServiceArgumentParser {
 public:
  ServiceArgumentParser(DWORD argc, const LPSTR* argv) {
    if (argc > 1) {
      for (DWORD i = 0; i < argc; i++) {
        args_.push_back(argv[i]);
      }
      owns_argv_ptrs_ = false;
    } else {
      int wargc = 0;
      LPWSTR* wargv = ::CommandLineToArgvW(::GetCommandLineW(), &wargc);

      if (wargv != nullptr) {
        for (int i = 0; i < wargc; i++) {
          LPSTR arg = toMBString(wargv[i]);

          // On error, bail out and clean up the vector
          if (arg == nullptr) {
            cleanArgs();
            ::LocalFree(wargv);
            break;
          }
          args_.push_back(arg);
        }
        owns_argv_ptrs_ = true;
        ::LocalFree(wargv);
      }
    }
  }

  ~ServiceArgumentParser() {
    cleanArgs();
  }

  DWORD count() const {
    return static_cast<DWORD>(args_.size());
  }
  LPSTR* arguments() {
    return args_.data();
  }

 private:
  LPSTR toMBString(const LPWSTR src) const {
    if (src == nullptr) {
      return nullptr;
    }

    size_t converted = 0;

    // Allocate the same amount for multi-byte
    size_t mbsbuf_size = wcslen(src) * 2;
    LPSTR mbsbuf = static_cast<LPSTR>(new char[mbsbuf_size]);
    if (mbsbuf == nullptr) {
      return nullptr;
    }

    if (wcstombs_s(&converted, mbsbuf, mbsbuf_size, src, mbsbuf_size) != 0) {
      delete[] mbsbuf;
      return nullptr;
    }

    return mbsbuf;
  }

  void cleanArgs() {
    if (owns_argv_ptrs_) {
      for (size_t i = 0; i < args_.size(); i++) {
        if (args_[i] != nullptr) {
          delete[] args_[i];
          args_[i] = nullptr;
        }
      }
    }
    args_.clear();
  }

  bool owns_argv_ptrs_{false};
  std::vector<LPSTR> args_;
};

// Set recovery behavior on service failure
static void setupServiceRecovery(SC_HANDLE schService) {
  SC_ACTION actionRestartService{};
  actionRestartService.Type = SC_ACTION_RESTART;
  actionRestartService.Delay = 5000; // delay in ms
  SC_ACTION actionNone{};
  actionNone.Type = SC_ACTION_NONE;

  // Try restarting once, on subsequent failures give up
  SC_ACTION actions[] = {actionRestartService, actionNone};

  SERVICE_FAILURE_ACTIONS failureActions{};
  failureActions.cActions = sizeof(actions) / sizeof(*actions);
  failureActions.lpsaActions = actions;

  if (!ChangeServiceConfig2(
          schService, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
    auto le = GetLastError();
    SLOG("ChangeServiceConfig2 failed (lasterror=" + std::to_string(le) + ")");
  }
}

/// Install osqueryd as a service given the path to the binary
Status installService(const std::string& binPath) {
  SC_HANDLE schSCManager = OpenSCManager(
      nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);

  if (schSCManager == nullptr) {
    return Status(1);
  }

  SC_HANDLE schService =
      OpenServiceA(schSCManager, kServiceName.c_str(), SERVICE_ALL_ACCESS);

  if (schService != nullptr) {
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return Status(1);
  }

  HANDLE flagsFilePtr = nullptr;
  auto binPathWithFlagFile = binPath + " --flagfile=";
  auto flagsFile = FLAGS_flagfile.empty() ? kDefaultFlagsFile : FLAGS_flagfile;
  // "Wrap" the flag file in the event there are spaces in the path. We do this
  // in a safer way in the event FLAGS_flagFile is already wrapped in quotes
  if (flagsFile[0] != '"') {
    flagsFile = "\"" + flagsFile;
  }
  if (flagsFile[flagsFile.size() - 1] != '"') {
    flagsFile = flagsFile + "\"";
  }
  binPathWithFlagFile += flagsFile;
  flagsFilePtr = CreateFileA(flagsFile.c_str(),
                             GENERIC_READ,
                             FILE_SHARE_READ,
                             nullptr,
                             OPEN_ALWAYS,
                             0,
                             nullptr);
  CloseHandle(flagsFilePtr);

  schService = CreateServiceA(schSCManager,
                              kServiceName.c_str(),
                              kServiceDisplayName.c_str(),
                              SERVICE_ALL_ACCESS,
                              SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_AUTO_START,
                              SERVICE_ERROR_NORMAL,
                              binPathWithFlagFile.c_str(),
                              nullptr,
                              nullptr,
                              nullptr,
                              nullptr,
                              nullptr);

  if (schService) {
    setupServiceRecovery(schService);
  }

  CloseServiceHandle(schSCManager);
  CloseServiceHandle(schService);
  return Status(schService ? 0 : 1);
}

Status uninstallService() {
  SC_HANDLE schSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (schSCManager == nullptr) {
    return Status(1);
  }

  SC_HANDLE schService =
      OpenServiceA(schSCManager,
                   kServiceName.c_str(),
                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);

  if (schService == nullptr) {
    CloseServiceHandle(schService);
    return Status(1);
  }

  SERVICE_STATUS_PROCESS ssStatus;
  DWORD dwBytesNeeded;
  if (!QueryServiceStatusEx(schService,
                            SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&ssStatus),
                            sizeof(SERVICE_STATUS_PROCESS),
                            &dwBytesNeeded)) {
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return Status(1);
  }

  SERVICE_STATUS ssSvcStatus = {};
  if (ssStatus.dwCurrentState != SERVICE_STOPPED) {
    ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus);
    // Wait 3 seconds to give the service an opportunity to stop.
    Sleep(3000);
    QueryServiceStatus(schService, &ssSvcStatus);
    if (ssSvcStatus.dwCurrentState != SERVICE_STOPPED) {
      CloseServiceHandle(schSCManager);
      CloseServiceHandle(schService);
      return Status(1);
    }
  }

  auto s = DeleteService(schService);
  CloseServiceHandle(schSCManager);
  CloseServiceHandle(schService);
  return Status(s ? 0 : 1);
}

void WINAPI ServiceControlHandler(DWORD control_code) {
  switch (control_code) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN: {
    if (kServiceStatus.dwCurrentState != SERVICE_RUNNING) {
      break;
    }

    // Give the main thread a chance to shutdown gracefully before exiting
    UpdateServiceStatus(0, SERVICE_STOP_PENDING, 0, 3, kServiceShutdownWait);

    requestShutdown();
    auto thread = OpenThread(SYNCHRONIZE, false, kLegacyThreadId);
    if (thread != nullptr) {
      WaitForSingleObjectEx(thread, INFINITE, FALSE);
      CloseHandle(thread);
    } else {
      auto le = GetLastError();
      SLOG("Failed to open handle to main thread of execution with " +
           std::to_string(le));
    }
    break;
  }
  default:
    break;
  }
}

void WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
  kStatusHandle = ::RegisterServiceCtrlHandlerA(kServiceName.c_str(),
                                                ServiceControlHandler);
  if (kStatusHandle != nullptr) {
    ::ZeroMemory(&kServiceStatus, sizeof(kServiceStatus));
    kServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    kServiceStatus.dwServiceSpecificExitCode = 0;
    UpdateServiceStatus(0, SERVICE_START_PENDING, 0, 0);
    UpdateServiceStatus(
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, SERVICE_RUNNING, 0, 0);

    ServiceArgumentParser parser(argc, argv);
    if (parser.count() == 0) {
      SLOG("ServiceArgumentParser failed (cmdline=" +
           std::string(GetCommandLineA()) + ")");
    } else {
      osquery::startOsquery(parser.count(), parser.arguments());
    }
  } else {
    auto le = GetLastError();
    SLOG("RegisterServiceCtrlHandlerA failed (lasterror=" + std::to_string(le) +
         ")");
  }

  UpdateServiceStatus(0, SERVICE_STOPPED, 0, 4);
}
} // namespace osquery

int main(int argc, char* argv[]) {
  osquery::initializeFilesystemAPILocale();

  SERVICE_TABLE_ENTRYA serviceTable[] = {
      {const_cast<CHAR*>(osquery::kServiceName.c_str()),
       static_cast<LPSERVICE_MAIN_FUNCTIONA>(osquery::ServiceMain)},
      {nullptr, nullptr}};

  int retcode = 0;
  if (!StartServiceCtrlDispatcherA(serviceTable)) {
    auto le = ::GetLastError();
    if (le == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      // Failing to start the service control dispatcher with this error
      // usually indicates that the process was not started as a service.
      // Therefore, it must've been started from the commandline or as a child
      // process
      retcode = osquery::startOsquery(argc, argv);
    } else {
      // An actual error has occurred at this point
      SLOG("StartServiceCtrlDispatcherA error (lasterror=" +
           std::to_string(le) + ")");
    }
  }
  return retcode;
}
