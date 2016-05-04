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
#include <stdlib.h>
#include <boost/optional.hpp>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "osquery/core/process.h"

namespace osquery {

PlatformProcess getCurrentProcess() {
  pid_t pid = ::getpid();
  return PlatformProcess(pid);
}

PlatformProcess getLauncherProcess() {
  pid_t ppid = ::getppid();
  return PlatformProcess(ppid);
}

bool isLauncherProcessDead(PlatformProcess& launcher) {
  if (!launcher.isValid()) {
    return false;
  }
  
  return (::getppid() != launcher.nativeHandle());
}

bool setEnvVar(const std::string& name, const std::string& value) {
  auto ret = ::setenv(name.c_str(), value.c_str(), 1);
  return (ret == 0);
}

bool unsetEnvVar(const std::string& name) {
  auto ret = ::unsetenv(name.c_str());
  return (ret == 0);
}

boost::optional<std::string> getEnvVar(const std::string& name) {
  char *value = ::getenv(name.c_str());
  if (value) {
    return std::string(value);
  }
  return boost::none;
}

void cleanupDefunctProcesses() {
  ::waitpid(-1, 0, WNOHANG);
}

ProcessState checkChildProcessStatus(const PlatformProcess& process, int& status) {
  int process_status = 0;
  
  pid_t result = ::waitpid(process.nativeHandle(), &process_status, WNOHANG);
  if (result < 0) {
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

void setToBackgroundPriority() {
  setpriority(PRIO_PGRP, 0, 10);
}
}
