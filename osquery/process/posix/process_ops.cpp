/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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

#include <osquery/core/flags.h>
#include <osquery/process/process.h>

namespace osquery {

DECLARE_uint64(alarm_timeout);

uint32_t platformGetUid() {
  return ::getuid();
}

bool isLauncherProcessDead(PlatformProcess& launcher) {
  if (!launcher.isValid()) {
    return true;
  }

  return (::getppid() != launcher.nativeHandle());
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
  return static_cast<int>(getpid());
}

uint64_t platformGetTid() {
  return std::hash<std::thread::id>()(std::this_thread::get_id());
}
}
