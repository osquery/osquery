/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "etw_helpers.h"

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace osquery {

std::string sidStringFromEtwRecord(const EVENT_RECORD& record) {
  if (record.ExtendedDataCount == 0 || record.ExtendedData == nullptr) {
    return "";
  }

  // Iterate through extended data to find EVENT_HEADER_EXT_TYPE_SID
  for (USHORT i = 0; i < record.ExtendedDataCount; ++i) {
    const EVENT_HEADER_EXTENDED_DATA_ITEM& data = record.ExtendedData[i];

    if (data.ExtType == EVENT_HEADER_EXT_TYPE_SID) {
      PSID userSid = reinterpret_cast<PSID>(data.DataPtr);
      if (userSid && IsValidSid(userSid)) {
        return psidToString(userSid);
      }
    }
  }
  return "";
}

std::string processImagePathFromProcessId(uint32_t processId) {
  // Open the process
  HANDLE hProcess = OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
  if (hProcess == NULL) {
    return "";
  }
  auto guard = scope_guard::create([&] { CloseHandle(hProcess); });

  // Get the path of the executable
  wchar_t processPath[MAX_PATH];
  DWORD length = GetProcessImageFileNameW(
      hProcess, processPath, sizeof(processPath) / sizeof(wchar_t));

  if (length == 0) {
    return "";
  }

  return wstringToString(processPath);
}

} // namespace osquery
