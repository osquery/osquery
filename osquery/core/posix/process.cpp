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

#include <signal.h>
#include <sys/types.h>

#include <osquery/logger.h>

#include "osquery/core/process.h"

extern char **environ;

namespace osquery {

PlatformProcess::PlatformProcess(PlatformPidType id)
  : id_(id) { }

PlatformProcess::PlatformProcess(const PlatformProcess& src) = default;
PlatformProcess::PlatformProcess(PlatformProcess&& src) = default;

PlatformProcess::~PlatformProcess() { }

PlatformProcess& PlatformProcess::operator=(const PlatformProcess& process) = default;

bool PlatformProcess::kill() {
  if (id_ == kInvalidPid) {
    return false;
  }
  
  int status = ::kill(id_, SIGKILL);
  return (status == 0);
}

PlatformProcess PlatformProcess::launchWorker(const std::string& exec_path, const std::string& name) {
  auto worker_pid = ::fork();
  if (worker_pid < 0) {
    return PlatformProcess(kInvalidPid);
  } else if (worker_pid == 0) {
    setEnvVar("OSQUERY_WORKER", std::to_string(::getpid()).c_str());
    ::execle(exec_path.c_str(), name.c_str(), nullptr, ::environ);
    
    // Code should never reach this point
    LOG(ERROR) << "osqueryd could not start worker process";
    Initializer::shutdown(EXIT_CATASTROPHIC);
    return PlatformProcess(kInvalidPid);
  }
  return PlatformProcess(worker_pid);
}

PlatformProcess PlatformProcess::launchExtension(const std::string& exec_path, 
                                                 const std::string& extension, 
                                                 const std::string& extensions_socket,
                                                 const std::string& extensions_timeout,
                                                 const std::string& extensions_interval,
                                                 const std::string& verbose) {
  auto ext_pid = ::fork();
  if (ext_pid < 0) {
    return PlatformProcess(kInvalidPid);
  } else if (ext_pid == 0) {
    setEnvVar("OSQUERY_EXTENSIONS", std::to_string(::getpid()).c_str());
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
    return PlatformProcess(kInvalidPid);
  }

  return PlatformProcess(ext_pid);
}

PlatformProcess PlatformProcess::fromPlatformPid(PlatformPidType id) {
  return PlatformProcess(id);
}
}

