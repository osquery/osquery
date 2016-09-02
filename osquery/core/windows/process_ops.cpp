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

#include <boost/optional.hpp>

#include "osquery/core/process.h"
#include "osquery/system.h"

namespace osquery {

bool isLauncherProcessDead(PlatformProcess& launcher) {
  DWORD code = 0;
  if (!::GetExitCodeProcess(launcher.nativeHandle(), &code)) {
    // TODO(#1991): If an error occurs with GetExitCodeProcess, do we want to
    // return a Status object to describe the error with more granularity?
    return false;
  }

  return (code != STILL_ACTIVE);
}

bool setEnvVar(const std::string& name, const std::string& value) {
  return (::SetEnvironmentVariableA(name.c_str(), value.c_str()) == TRUE);
}

bool unsetEnvVar(const std::string& name) {
  return (::SetEnvironmentVariableA(name.c_str(), NULL) == TRUE);
}

boost::optional<std::string> getEnvVar(const std::string& name) {
  const int kInitialBufferSize = 1024;
  std::vector<char> buf;
  buf.assign(kInitialBufferSize, '\0');

  DWORD value_len =
      ::GetEnvironmentVariableA(name.c_str(), buf.data(), kInitialBufferSize);
  if (value_len == 0) {
    // TODO(#1991): Do we want figure out a way to be more granular in terms of
    // the error to return?
    return boost::none;
  }

  // It is always possible that between the first GetEnvironmentVariableA call
  // and this one, a change was made to our target environment variable that
  // altered the size. Currently, we ignore this scenario and fail if the
  // returned size is greater than what we expect.
  if (value_len > kInitialBufferSize) {
    buf.assign(value_len, '\0');
    value_len = ::GetEnvironmentVariableA(name.c_str(), buf.data(), value_len);
    if (value_len == 0 || value_len > buf.size()) {
      // The size returned is greater than the size we expected. Currently, we
      // will not deal with this scenario and just return as if an error has
      // occurred.
      return boost::none;
    }
  }

  return std::string(buf.data(), value_len);
}

ModuleHandle platformModuleOpen(const std::string &path) {
  return ::LoadLibraryA(path.c_str());
}

void *platformModuleGetSymbol(ModuleHandle module, const std::string &symbol) {
  return ::GetProcAddress(module, symbol.c_str());
}

std::string platformModuleGetError() {
  return std::string("GetLastError() = " + ::GetLastError());
}

bool platformModuleClose(ModuleHandle module) {
  return (::FreeLibrary(module) != 0);
}

void cleanupDefunctProcesses() {}

void setToBackgroundPriority() {}

// Helper function to determine if thread is running with admin privilege.
bool isUserAdmin() {
  HANDLE hToken = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    return false;
  }
  TOKEN_ELEVATION Elevation;
  DWORD cbSize = sizeof(TOKEN_ELEVATION);
  if (GetTokenInformation(
          hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize) ==
      0) {
    CloseHandle(hToken);
    return false;
  }
  if (hToken != nullptr) {
    CloseHandle(hToken);
  }
  return Elevation.TokenIsElevated ? true : false;
}
}
