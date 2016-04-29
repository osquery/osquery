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

#include "osquery/core/process.h"

namespace osquery 
{

PlatformProcess getCurrentProcess()
{
  pid_t pid = ::getpid();
  return PlatformProcess::fromPlatformPid(pid);
}

PlatformProcess getLauncherProcess()
{
  pid_t ppid = ::getppid();
  return PlatformProcess::fromPlatformPid(ppid);
}

bool isLauncherProcessDead(PlatformProcess& launcher)
{
  return (::getppid() != launcher.nativeHandle());
}

bool setEnvVar(const std::string& name, const std::string& value)
{
  auto ret = ::setenv(name.c_str(), value.c_str(), 1);
  return (ret == 0);
}

boost::optional<std::string> getEnvVar(const std::string& name)
{
  char *value = ::getenv(name.c_str());
  if (value) {
    return std::string(value);
  }
  return boost::none;
}

}
