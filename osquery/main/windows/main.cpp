/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <Windows.h>
#include <shellapi.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/watcher.h"
#include "osquery/main/main.h"

DECLARE_string(flagfile);

namespace osquery {

static const std::string kDefaultFlagsFile{OSQUERY_HOME "\\osquery.flags"};
static const std::string kServiceName{"osqueryd"};
static const std::string kServiceDisplayName{"osquery daemon service"};

const int kServiceShutdownTimeout {500};

static SERVICE_STATUS_HANDLE kStatusHandle = nullptr;
static SERVICE_STATUS kServiceStatus = {0};

/*
 * This event is set when a SERVICE_CONTROL_STOP or SERVICE_CONTROL_SHUTDOWN
 * message is received in the ServiceControlHandler
 */
static const std::string kStopEventName{"osqueryd-service-stop-event"};

/// Logging for when we need to debug this service
#define SLOG(s) ::osquery::DebugPrintf(s)

void DebugPrintf(const std::string& s) {
  auto dbgString = "[osqueryd] " + s;
  if (IsDebuggerPresent()) {
    ::OutputDebugStringA(dbgString.c_str());
  }
  LOG(ERROR) << s;
}

// A helper function to return a HANDLE to the named Stop Event for child
// processes
HANDLE getStopEvent() {
  auto stopEvent = ::OpenEventA(
      SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, osquery::kStopEventName.c_str());

  if (stopEvent == nullptr) {
    return stopEvent;
  }

  auto ret = WaitForSingleObject(stopEvent, 0);

  // The object has already been signaled
  if (ret == WAIT_OBJECT_0) {
    return nullptr;
  }

  // ERROR_FILE_NOT_FOUND indicates the event was never created.
  // Likely the process running as the daemon at the command line.
  if (stopEvent == nullptr && GetLastError() != ERROR_FILE_NOT_FOUND) {
    SLOG("OpenEventA failed for event name " + osquery::kStopEventName +
         " (lasterror=" + std::to_string(GetLastError()) + ")");
  }
  return stopEvent;
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
    SLOG("SetServiceStatus failed (lasterror=" +
         std::to_string(GetLastError()) + ")");
  }
}

static auto kShutdownCallable = ([]() {
  // To prevent invalid access to the stop event, we return if running as shell
  if (Initializer::isShell()) {
    return;
  }
  // The event only gets initialized in the entry point of the service. Child
  // processes and those run from the commandline will not have a stop event.
  auto stopEvent = osquery::getStopEvent();
  if (stopEvent != nullptr) {
    // Wait forever, until the service handler signals us
    ::WaitForSingleObject(stopEvent, INFINITE);
    
    // Interupt the worker service threads before joining
    Dispatcher::stopServices();

    auto ret = ::CloseHandle(stopEvent);
    if (ret != TRUE) {
      SLOG("kShutdownCallable failed to call CloseHandle with (" +
           std::to_string(GetLastError()) + ")");
    }
  }
});

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

/// Install osqueryd as a service given the path to the binary
Status installService(const char* const binPath) {
  SC_HANDLE schSCManager = OpenSCManager(
      nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);

  if (schSCManager == nullptr) {
    return Status(1);
  }

  SC_HANDLE schService =
      OpenService(schSCManager, kServiceName.c_str(), SERVICE_ALL_ACCESS);

  if (schService != nullptr) {
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return Status(1);
  }

  HANDLE flagsFilePtr = nullptr;
  std::string binPathWithFlagFile = std::string(binPath) + " --flagfile=";
  std::string flagsFile =
      FLAGS_flagfile.empty() ? kDefaultFlagsFile : FLAGS_flagfile;
  binPathWithFlagFile += flagsFile;
  flagsFilePtr = CreateFile(flagsFile.c_str(),
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_ALWAYS,
                            0,
                            nullptr);
  CloseHandle(flagsFilePtr);

  schService = CreateService(schSCManager,
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
                             nullptr, // User Account. nullptr => LOCAL SYSTEM
                             nullptr);

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
      OpenService(schSCManager,
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
  case SERVICE_CONTROL_SHUTDOWN:
    if (kServiceStatus.dwCurrentState != SERVICE_RUNNING) {
      break;
    }

    UpdateServiceStatus(0, SERVICE_STOP_PENDING, 0, 3, 2 * kServiceShutdownTimeout);
    {
      auto stopEvent = osquery::getStopEvent();
      if (stopEvent != nullptr) {
        auto ret = SetEvent(stopEvent);
        if (ret != TRUE) {
          SLOG("SetEvent failed (lasterror=" + std::to_string(GetLastError()) +
               ")");
        }
        CloseHandle(stopEvent);
      }
      // We allow for the watcher primary thread of execution to
      // shutdown gracefully by pausing for 500 ms. This is set 
      //Sleep(kServiceShutdownTimeout);
      unsigned long tid = static_cast<unsigned long>(std::hash<std::thread::id>{}(kMainThreadId));
      auto mainThread = OpenThread(SYNCHRONIZE, false, tid);
      WaitForSingleObjectEx(mainThread, kServiceShutdownTimeout, true);

      // Lastly wait for our child process to shut down
      auto& worker = Watcher::get().getWorker();
      WaitForSingleObjectEx(worker.nativeHandle(), kServiceShutdownTimeout, true);
    }
    UpdateServiceStatus(0, SERVICE_STOPPED, 0, 4);

    break;
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

    auto stopEvent =
        ::CreateEventA(nullptr, TRUE, FALSE, kStopEventName.c_str());
    if (stopEvent != nullptr) {
      UpdateServiceStatus(
          SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, SERVICE_RUNNING, 0, 0);

      ServiceArgumentParser parser(argc, argv);
      if (parser.count() == 0) {
        SLOG("ServiceArgumentParser failed (cmdline=" +
             std::string(GetCommandLineA()) + ")");
      } else {
        osquery::startOsquery(
            parser.count(), parser.arguments(), kShutdownCallable);
      }

      ::CloseHandle(stopEvent);
    } else {
      SLOG("CreateEventA failed (lasterror=" + std::to_string(GetLastError()) +
           ")");
    }
  } else {
    SLOG("RegisterServiceCtrlHandlerA failed (lasterror=" +
         std::to_string(GetLastError()) + ")");
  }

  UpdateServiceStatus(0, SERVICE_STOPPED, 0, 4);
}
} // namespace osquery

int main(int argc, char* argv[]) {
  SERVICE_TABLE_ENTRYA serviceTable[] = {
      {const_cast<CHAR*>(osquery::kServiceName.c_str()),
       static_cast<LPSERVICE_MAIN_FUNCTION>(osquery::ServiceMain)},
      {nullptr, nullptr}};

  if (!::StartServiceCtrlDispatcherA(serviceTable)) {
    DWORD last_error = ::GetLastError();
    if (last_error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      // Failing to start the service control dispatcher with this error
      // usually indicates that the process was not started as a service.
      // Therefore, it must've been started from the commandline or as a child
      // process
      osquery::startOsquery(argc, argv, osquery::kShutdownCallable);
    } else {
      // An actual error has occurred at this point
      SLOG("StartServiceCtrlDispatcherA error (lasterror=" +
           std::to_string(last_error) + ")");
    }
  }
  return 0;
}
