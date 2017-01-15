/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <vector>

#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/process.h"

extern char** environ;

namespace osquery {

PlatformProcess::PlatformProcess(PlatformPidType id) : id_(id) {}

bool PlatformProcess::operator==(const PlatformProcess& process) const {
  return (nativeHandle() == process.nativeHandle());
}

bool PlatformProcess::operator!=(const PlatformProcess& process) const {
  return (nativeHandle() != process.nativeHandle());
}

PlatformProcess::~PlatformProcess() {}

int PlatformProcess::pid() const {
  return id_;
}

bool PlatformProcess::kill() const {
  if (!isValid()) {
    return false;
  }

  int status = ::kill(nativeHandle(), SIGKILL);
  return (status == 0);
}

bool PlatformProcess::killGracefully() const {
  if (!isValid()) {
    return false;
  }

  int status = ::kill(nativeHandle(), SIGINT);
  return (status == 0);
}

ProcessState PlatformProcess::checkStatus(int& status) const {
  int process_status = 0;

  pid_t result = ::waitpid(nativeHandle(), &process_status, WNOHANG);
  if (result < 0) {
    if (errno == ECHILD) {
      return PROCESS_EXITED;
    }
    return PROCESS_ERROR;
  }

  if (result == 0) {
    return PROCESS_STILL_ALIVE;
  }

  if (WIFEXITED(process_status)) {
    status = WEXITSTATUS(process_status);
    return PROCESS_EXITED;
  }

  // process's state has changed but the state isn't that which we expect!
  return PROCESS_STATE_CHANGE;
}

std::shared_ptr<PlatformProcess> PlatformProcess::getCurrentProcess() {
  pid_t pid = ::getpid();
  return std::make_shared<PlatformProcess>(pid);
}

std::shared_ptr<PlatformProcess> PlatformProcess::getLauncherProcess() {
  pid_t ppid = ::getppid();
  return std::make_shared<PlatformProcess>(ppid);
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchWorker(
    const std::string& exec_path, int argc /* unused */, char** argv) {
  auto worker_pid = ::fork();
  if (worker_pid < 0) {
    return std::shared_ptr<PlatformProcess>();
  } else if (worker_pid == 0) {
    setEnvVar("OSQUERY_WORKER", std::to_string(::getpid()).c_str());
    ::execve(exec_path.c_str(), argv, ::environ);

    // Code should never reach this point
    LOG(ERROR) << "osqueryd could not start worker process";
    Initializer::shutdown(EXIT_CATASTROPHIC);
    return std::shared_ptr<PlatformProcess>();
  }
  return std::make_shared<PlatformProcess>(worker_pid);
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchExtension(
    const std::string& exec_path,
    const std::string& extension,
    const std::string& extensions_socket,
    const std::string& extensions_timeout,
    const std::string& extensions_interval,
    const std::string& verbose) {
  auto ext_pid = ::fork();
  if (ext_pid < 0) {
    return std::shared_ptr<PlatformProcess>();
  } else if (ext_pid == 0) {
    setEnvVar("OSQUERY_EXTENSION", std::to_string(::getpid()).c_str());
    ::execle(exec_path.c_str(),
             ("osquery extension: " + extension).c_str(),
             "--socket",
             extensions_socket.c_str(),
             "--timeout",
             extensions_timeout.c_str(),
             "--interval",
             extensions_interval.c_str(),
             (verbose == "true") ? "--verbose" : (char*)nullptr,
             (char*)nullptr,
             ::environ);

    // Code should never reach this point
    VLOG(1) << "Could not start extension process: " << extension;
    Initializer::shutdown(EXIT_FAILURE);
    return std::shared_ptr<PlatformProcess>();
  }

  return std::make_shared<PlatformProcess>(ext_pid);
}

std::shared_ptr<PlatformProcess> PlatformProcess::launchPythonScript(
    const std::string& args) {
  std::shared_ptr<PlatformProcess> process;

  std::string argv = "/usr/local/osquery/bin/python " + args;

  int process_pid = ::fork();
  if (process_pid == 0) {
    // Start a Python script
    ::execlp("sh", "sh", "-c", argv.c_str(), nullptr);
    ::exit(0);
  } else if (process_pid > 0) {
    process.reset(new PlatformProcess(process_pid));
  }

  return process;
}
}
