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
#include <vector>
#include <stdlib.h>
#include <boost/optional.hpp>

#include "osquery/core/process.h"

namespace osquery 
{

PlatformProcess getCurrentProcess()
{
  // OpenProcess with GetCurrentProcessId with full privileges
  return PlatformProcess(kInvalidPid);
}

PlatformProcess getLauncherProcess()
{
  // Check for existence of OSQUERY_LAUNCHER
  return PlatformProcess(kInvalidPid);  
}

bool isLauncherProcessDead(PlatformProcess& launcher)
{
  DWORD code = 0 ;
  if (!::GetExitCodeProcess(launcher.nativeHandle(), &code)) {
    // TODO: how do we propogate an error?
    return false;
  }
  
  return (code != STILL_ACTIVE);
}

bool setEnvVar(const std::string& name, const std::string& value)
{
  return (::SetEnvironmentVariableA(name.c_str(), value.c_str()) == TRUE);
}

boost::optional<std::string> getEnvVar(const std::string& name)
{
  const int kInitialBufferSize = 1024;
  std::vector<char> buf;
  buf.assign(kInitialBufferSize, '\0');
  
  DWORD value_len = ::GetEnvironmentVariableA(name.c_str(), &buf[0], kInitialBufferSize);
  if (value_len == 0) {
    // Either environment variable name is invalid or something has gone horribly wrong
    return boost::none;
  }
  
  // We understand that there is always the possibility of a race-condition
  if (value_len > kInitialBufferSize) {
    buf.assign(value_len, '\0');
    value_len = ::GetEnvironmentVariableA(name.c_str(), &buf[0], value_len);
    if (value_len == 0 || value_len > buf.size()) {
      // Could not retrieve environment variable
      
      return boost::none;
    }
  }
  
  return std::string(&buf[0], value_len);
}

}
