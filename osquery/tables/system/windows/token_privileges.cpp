/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <osquery/core/shutdown.h>
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
using ScopedHandle =
    std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

SeDebugPrivState getDebugTokenPrivilegeState() noexcept {
  HANDLE hToken = NULL;

  // Open the current process's token with query access
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    return SeDebugPrivState::Disabled; // If we can't open the token, assume the
                                       // privilege is disabled
  }

  // Ensure the token handle is closed when we're done
  ScopedHandle token(hToken);

  // First call to get required buffer size
  DWORD length = 0;
  GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &length);
  if (length == 0) {
    return SeDebugPrivState::Disabled; // If we can't get the required buffer
                                       // size, assume the privilege is disabled
  }

  // Allocate buffer and call again to get the actual privileges
  auto buffer = std::unique_ptr<BYTE[]>(new (std::nothrow) BYTE[length]);
  if (!buffer) {
    return SeDebugPrivState::Disabled; // If we can't allocate the buffer,
                                       // assume the privilege is disabled
  }
  auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.get());
  if (!GetTokenInformation(
          hToken, TokenPrivileges, privileges, length, &length)) {
    return SeDebugPrivState::Disabled; // If we can't get the privileges, assume
                                       // it's disabled
  }

  // Get the LUID for the debug privilege, so we can find it in the token's
  // privileges list
  LUID debugLuid = {0};
  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugLuid)) {
    return SeDebugPrivState::Disabled; // If we can't lookup the privilege,
                                       // assume it's disabled
  }

  auto isDebugLuid = [&debugLuid](const LUID& luid) {
    return luid.LowPart == debugLuid.LowPart &&
           luid.HighPart == debugLuid.HighPart;
  };

  auto isDebugPrivEnabled = [](const LUID_AND_ATTRIBUTES& privilege) {
    return (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0;
  };

  // Walk the token's privileges to find the debug privilege and check if it's
  // enabled
  for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
    if (isDebugLuid(privileges->Privileges[i].Luid)) {
      if (isDebugPrivEnabled(privileges->Privileges[i])) {
        return SeDebugPrivState::Enabled;
      } else {
        return SeDebugPrivState::Disabled;
      }
    }
  }

  return SeDebugPrivState::Disabled; // If we didn't find the privilege, it's
                                     // disabled
}

static bool setDebugTokenPrivilege(SeDebugPrivState state) noexcept {
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tp = {0};
  LUID val = {0};

  // Open the current process's token with adjust privileges and query access
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                        &hToken)) {
    return false;
  }

  // Ensure the token handle is closed when we're done
  ScopedHandle token(hToken);

  // Lookup the LUID for the debug privilege
  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &val)) {
    return false;
  }

  // Set the token privileges structure to enable or disable the debug privilege
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = val;
  tp.Privileges[0].Attributes =
      state == SeDebugPrivState::Enabled ? SE_PRIVILEGE_ENABLED : 0;
  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL)) {
    return false;
  }

  // AdjustTokenPrivileges can succeed but still fail to enable the privilege
  // if it's not assigned to the token
  if (ERROR_NOT_ALL_ASSIGNED == GetLastError()) {
    return false;
  }

  return true;
}

SeDebugPrivilegeGuard::SeDebugPrivilegeGuard() noexcept {
  std::unique_lock<std::mutex> lock(s_mutex);
  s_ref_count++;

  if (s_ref_count > 1) {
    return;
  }

  s_original_state = getDebugTokenPrivilegeState();
  if (s_original_state == SeDebugPrivState::Enabled) {
    s_needs_reset = false;
    return;
  }

  s_needs_reset = setDebugTokenPrivilege(SeDebugPrivState::Enabled);
  if (!s_needs_reset) {
    LOG(ERROR) << "Failed to enable debug token privilege. Handle enumeration "
                  "may be incomplete for processes we don't own";
    return;
  }
}

SeDebugPrivilegeGuard::~SeDebugPrivilegeGuard() noexcept {
  std::unique_lock<std::mutex> lock(s_mutex);
  s_ref_count--;

  if (s_ref_count == 0 && s_needs_reset) {
    setDebugTokenPrivilege(s_original_state);
  }
}

int SeDebugPrivilegeGuard::refCount() const {
  std::unique_lock<std::mutex> lock(s_mutex);
  return s_ref_count;
}

} // namespace tables
} // namespace osquery
