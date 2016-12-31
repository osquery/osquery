/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <string>
#include <vector>

#include <boost/optional.hpp>

#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {

int platformGetUid() {
  DWORD nbytes = 0;
  HANDLE token = INVALID_HANDLE_VALUE;

  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return -1;
  }

  ::GetTokenInformation(token, TokenUser, nullptr, 0, &nbytes);
  if (nbytes == 0) {
    ::CloseHandle(token);
    return -1;
  }

  std::vector<char> tu_buffer;
  tu_buffer.assign(nbytes, '\0');
  PTOKEN_USER tu = nullptr;

  BOOL status = ::GetTokenInformation(token,
                                      TokenUser,
                                      tu_buffer.data(),
                                      static_cast<DWORD>(tu_buffer.size()),
                                      &nbytes);
  ::CloseHandle(token);
  if (status == 0) {
    return -1;
  }

  LPSTR sid = nullptr;
  tu = (PTOKEN_USER)tu_buffer.data();
  SID_NAME_USE eUse = SidTypeUnknown;
  DWORD unameSize = 0;
  DWORD domNameSize = 1;

  // LookupAccountSid first gets the size of the username buff required.
  LookupAccountSid(
      nullptr, tu->User.Sid, nullptr, &unameSize, nullptr, &domNameSize, &eUse);

  std::vector<char> uname(unameSize);
  std::vector<char> domName(domNameSize);
  auto ret = LookupAccountSid(nullptr,
                              tu->User.Sid,
                              uname.data(),
                              &unameSize,
                              domName.data(),
                              &domNameSize,
                              &eUse);

  if (ret == 0) {
    return -1;
  }

  // USER_INFO_3 struct contains the RID (uid) of our user
  DWORD userInfoLevel = 3;
  LPUSER_INFO_3 userBuff = nullptr;
  std::wstring wideUserName = stringToWstring(std::string(uname.data()));
  ret = NetUserGetInfo(
      nullptr, wideUserName.c_str(), userInfoLevel, (LPBYTE*)&userBuff);

  if (ret != NERR_Success) {
    return -1;
  }

  ::LocalFree(sid);
  return userBuff->usri3_user_id;
}

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
  return (::SetEnvironmentVariableA(name.c_str(), nullptr) == TRUE);
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

ModuleHandle platformModuleOpen(const std::string& path) {
  return ::LoadLibraryA(path.c_str());
}

void* platformModuleGetSymbol(ModuleHandle module, const std::string& symbol) {
  return ::GetProcAddress(static_cast<HMODULE>(module), symbol.c_str());
}

std::string platformModuleGetError() {
  return std::string("GetLastError() = " + ::GetLastError());
}

bool platformModuleClose(ModuleHandle module) {
  return (::FreeLibrary(static_cast<HMODULE>(module)) != 0);
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

int platformGetPid() {
  return (int)GetCurrentProcessId();
}

int platformGetTid() {
  return (int)GetCurrentThreadId();
}
}
