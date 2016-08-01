/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/watcher.h"
#include "osquery/dispatcher/distributed.h"
#include "osquery/dispatcher/scheduler.h"

namespace osquery {

const std::string kServiceName = "osquery daemon service";
const std::string kWatcherWorkerName = "osqueryd: worker";

/// This event is set when a SERVICE_CONTROL_STOP or SERVICE_CONTROL_SHUTDOWN is
/// received
static HANDLE kStopEvent = nullptr;

static SERVICE_STATUS_HANDLE kStatusHandle = nullptr;
static SERVICE_STATUS kServiceStatus = { 0 };

/// Logging for when we need to debug this service
#define SLOG(...)  ::osquery::DebugPrintf("[osqueryd] " __VA_ARGS__)

void DebugPrintf(const char *fmt, ...) {
  va_list vl;
  va_start(vl, fmt);

  int size = _vscprintf(fmt, vl);
  if (size > 0) {
    char *buf = (char *)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
    if (buf != nullptr) {
      _vsprintf_p(buf, size + 1, fmt, vl);
      ::OutputDebugStringA(buf);
      ::HeapFree(GetProcessHeap(), 0, buf);
    }
  }

  va_end(vl);
}

void UpdateServiceStatus(DWORD controls, DWORD state, DWORD exit_code, DWORD checkpoint) {
  kServiceStatus.dwControlsAccepted = controls;
  kServiceStatus.dwCurrentState = state;
  kServiceStatus.dwWin32ExitCode = exit_code;
  kServiceStatus.dwCheckPoint = checkpoint;

  if (!::SetServiceStatus(kStatusHandle, &kServiceStatus)) {
    SLOG("SetServiceStatus failed (lasterror=%i)", ::GetLastError());
  }
}

void WINAPI ServiceControlHandler(DWORD control_code) {
  switch (control_code) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    if (kServiceStatus.dwCurrentState != SERVICE_RUNNING) {
      break;
    }

    UpdateServiceStatus(0, SERVICE_STOP_PENDING, 0, 4);

    ::SetEvent(kStopEvent);
    break;
  default:
    break;
  }
}

void daemonEntry(int argc, char *argv[]) {
  osquery::Initializer runner(argc, argv, osquery::OSQUERY_TOOL_DAEMON);

  if (!runner.isWorker()) {
    runner.initDaemon();
  }

  // When a watchdog is used, the current daemon will fork/exec into a worker.
  // In either case the watcher may start optionally loaded extensions.
  if (runner.isWorker()) {
    runner.initWorker(kWatcherWorkerName);
  } else {
    runner.initWatcher();

    // The event only gets initialized in the entry point of the service. Child
    // processes and those run from the commandline will have kStopEvent as a
    // nullptr
    if (kStopEvent != nullptr) {
      ::WaitForSingleObject(kStopEvent, INFINITE);

      runner.requestShutdown();
    }

    runner.waitForWatcher();
  }

  // Start osquery work.
  runner.start();

  // Conditionally begin the distributed query service
  auto s = osquery::startDistributed();
  if (!s.ok()) {
    VLOG(1) << "Not starting the distributed query service: " << s.toString();
  }

  // Begin the schedule runloop.
  osquery::startScheduler();

  // kStopEvent is nullptr if not run from the service control manager
  if (kStopEvent != nullptr) {
    ::WaitForSingleObject(kStopEvent, INFINITE);

    runner.requestShutdown();
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
}

void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
  kStatusHandle = ::RegisterServiceCtrlHandlerA(kServiceName.c_str(),
                                                ServiceControlHandler);
  if (kStatusHandle != nullptr) {
    ::ZeroMemory(&kServiceStatus, sizeof(kServiceStatus));
    kServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    kServiceStatus.dwServiceSpecificExitCode = 0;
    UpdateServiceStatus(0, SERVICE_START_PENDING, 0, 0);

    kStopEvent = ::CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (kStopEvent != nullptr) {
      UpdateServiceStatus(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                          SERVICE_RUNNING, 0, 0);

      daemonEntry(argc, argv);

      ::CloseHandle(kStopEvent);
      kStopEvent = nullptr;
    } else {
      SLOG("CreateEventA failed (lasterror=%i)", ::GetLastError());
    }
  } else {
    SLOG("RegisterServiceCtrlHandlerA failed (lasterror=%i)", ::GetLastError());
  }

  UpdateServiceStatus(0, SERVICE_STOPPED, 0, 3);
}
}

int main(int argc, char *argv[]) {
  SERVICE_TABLE_ENTRYA serviceTable[] = {
      {(LPSTR)osquery::kServiceName.c_str(), (LPSERVICE_MAIN_FUNCTION)osquery::ServiceMain},
      {nullptr, nullptr}};

  if (!::StartServiceCtrlDispatcherA(serviceTable)) {
    DWORD last_error = ::GetLastError();
    if (last_error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      // Failing to start the service control dispatcher with this error
      // usually indicates that the process was not started as a service.
      // Therefore, it must've been started from the commandline or as a child
      // process
      osquery::daemonEntry(argc, argv);
    } else {
      // An actual error has occurred at this point
      SLOG("StartServiceCtrlDispatcherA error (lasterror=%i)",
           ::GetLastError());
    }
  }
  return 0;
}
