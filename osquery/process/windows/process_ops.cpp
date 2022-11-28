/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

namespace osquery {

uint32_t platformGetUid() {
  auto gid_default = static_cast<uint32_t>(-1);
  auto token = INVALID_HANDLE_VALUE;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return gid_default;
  }

  unsigned long nbytes = 0;
  ::GetTokenInformation(token, TokenUser, nullptr, 0, &nbytes);
  if (nbytes == 0) {
    ::CloseHandle(token);
    return gid_default;
  }

  std::vector<char> tu_buffer;
  tu_buffer.assign(nbytes, '\0');

  auto status = ::GetTokenInformation(token,
                                      TokenUser,
                                      tu_buffer.data(),
                                      static_cast<DWORD>(tu_buffer.size()),
                                      &nbytes);
  ::CloseHandle(token);
  if (status == 0) {
    return gid_default;
  }

  auto tu = PTOKEN_USER(tu_buffer.data());
  return getRidFromSid(tu->User.Sid);
}

bool isLauncherProcessDead(PlatformProcess& launcher) {
  unsigned long code = 0;
  if (launcher.nativeHandle() == INVALID_HANDLE_VALUE) {
    return true;
  }

  if (!::GetExitCodeProcess(launcher.nativeHandle(), &code)) {
    LOG(WARNING) << "GetExitCodeProcess did not return a value, error code ("
                 << GetLastError() << ")";
    return false;
  }
  return (code != STILL_ACTIVE);
}

ModuleHandle platformModuleOpen(const std::string& path) {
  return ::LoadLibraryExW(
      stringToWstring(path).c_str(), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

void* platformModuleGetSymbol(ModuleHandle module, const std::string& symbol) {
  return ::GetProcAddress(static_cast<HMODULE>(module), symbol.c_str());
}

std::string platformModuleGetError() {
  return std::string("GetLastError() = " + std::to_string(::GetLastError()));
}

bool platformModuleClose(ModuleHandle module) {
  return (::FreeLibrary(static_cast<HMODULE>(module)) != 0);
}

void setToBackgroundPriority() {
  auto ret =
      SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
  if (ret != TRUE) {
    LOG(WARNING) << "Failed to set background process priority with "
                 << GetLastError();
  }
}

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
  return static_cast<int>(GetCurrentProcessId());
}

uint64_t platformGetTid() {
  return GetCurrentThreadId();
}
} // namespace osquery
