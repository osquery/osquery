/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <memory>

#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/token_privileges.h>

namespace osquery {
namespace tables {

struct HandleDeleter {
  void operator()(HANDLE h) const {
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
      CloseHandle(h);
    }
  }
};
using UniqueHandle =
    std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

SeDebugPrivState getDebugTokenPrivilegeState() {
  HANDLE hToken = NULL;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    LOG(ERROR) << "OpenProcessToken failed: " << GetLastError();
    return SeDebugPrivState::Disabled;
  }
  UniqueHandle token(hToken);

  // First call to get required buffer size
  DWORD length = 0;
  GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &length);

  std::vector<BYTE> buffer(length);
  auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());

  if (!GetTokenInformation(
          hToken, TokenPrivileges, privileges, length, &length)) {
    LOG(ERROR) << "GetTokenInformation failed: " << GetLastError();
    return SeDebugPrivState::Disabled;
  }

  LUID debugLuid = {0};
  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugLuid)) {
    LOG(ERROR) << "LookupPrivilegeValue failed: " << GetLastError();
    return SeDebugPrivState::Disabled;
  }

  for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
    if (privileges->Privileges[i].Luid.LowPart == debugLuid.LowPart &&
        privileges->Privileges[i].Luid.HighPart == debugLuid.HighPart) {
      return (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0
                 ? SeDebugPrivState::Enabled
                 : SeDebugPrivState::Disabled;
    }
  }

  return SeDebugPrivState::Disabled;
}

bool setDebugTokenPrivilege(SeDebugPrivState state) {
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tp = {0};
  LUID val = {0};

  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                        &hToken)) {
    LOG(ERROR) << "OpenProcessToken failed: " << GetLastError();
    return false;
  }
  UniqueHandle token(hToken);

  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &val)) {
    LOG(ERROR) << "LookupPrivilegeValue failed: " << GetLastError();
    return false;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = val;
  tp.Privileges[0].Attributes =
      state == SeDebugPrivState::Enabled ? SE_PRIVILEGE_ENABLED : 0;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL)) {
    LOG(ERROR) << "AdjustTokenPrivileges failed: " << GetLastError();
    return false;
  }

  if (ERROR_NOT_ALL_ASSIGNED == GetLastError()) {
    return false;
  }

  return true;
}

} // namespace tables
} // namespace osquery
