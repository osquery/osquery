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

#include <dlfcn.h>
#include <stdlib.h>

#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <boost/optional.hpp>

#include <osquery/flags.h>

#include "osquery/core/process.h"

namespace osquery {

DECLARE_uint64(alarm_timeout);

int platformGetUid() {
  return ::getuid();
}

bool isLauncherProcessDead(PlatformProcess& launcher) {
  if (!launcher.isValid()) {
    return true;
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
  char* value = ::getenv(name.c_str());
  if (value) {
    return std::string(value);
  }
  return boost::none;
}

ModuleHandle platformModuleOpen(const std::string& path) {
  return ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
}

void* platformModuleGetSymbol(ModuleHandle module, const std::string& symbol) {
  return ::dlsym(module, symbol.c_str());
}

std::string platformModuleGetError() {
  return ::dlerror();
}

bool platformModuleClose(ModuleHandle module) {
  return (::dlclose(module) == 0);
}

void setToBackgroundPriority() {
  setpriority(PRIO_PGRP, 0, 10);
}

// Helper function to determine if thread is running with admin privilege.
bool isUserAdmin() {
  return getuid() == 0;
}

int platformGetPid() {
  return (int)getpid();
}

int platformGetTid() {
#if defined(__APPLE__) || defined(FREEBSD)
  return std::hash<std::thread::id>()(std::this_thread::get_id());
#else
  return (int)syscall(SYS_gettid);
#endif
}
}
