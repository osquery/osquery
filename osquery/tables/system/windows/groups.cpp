/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/core/windows/process_ops.h"
#include "osquery/tables/system/windows/registry.h"
#include "osquery/core/conversions.h"

namespace osquery {

namespace tables {

void processLocalGroups(QueryData& results) {
  unsigned long groupInfoLevel = 1;
  unsigned long numGroupsRead = 0;
  unsigned long totalGroups = 0;
  unsigned long resumeHandle = 0;
  unsigned long ret = 0;
  LOCALGROUP_INFO_1* lginfo = nullptr;

  std::unique_ptr<BYTE[]> sidSmartPtr = nullptr;
  PSID sidPtr = nullptr;

  do {
    ret = NetLocalGroupEnum(nullptr,
                            groupInfoLevel,
                            (LPBYTE*)&lginfo,
                            MAX_PREFERRED_LENGTH,
                            &numGroupsRead,
                            &totalGroups,
                            nullptr);

    if (lginfo == nullptr || (ret != NERR_Success && ret != ERROR_MORE_DATA)) {
      LOG(INFO) << "NetLocalGroupEnum failed with return value: " << ret;
      break;
    }

    for (size_t i = 0; i < numGroupsRead; i++) {
      Row r;
      sidSmartPtr = getSidFromUsername(lginfo[i].lgrpi1_name);

      if (sidSmartPtr != nullptr) {
        sidPtr = static_cast<PSID>(sidSmartPtr.get());

        // Windows' extended schema, including full SID and comment strings:
        r["group_sid"] = psidToString(sidPtr);
        r["comment"] = wstringToString(lginfo[i].lgrpi1_comment);

        // Common schema, normalizing group information with POSIX:
        r["gid"] = INTEGER(getRidFromSid(sidPtr));
        r["gid_signed"] = INTEGER(getRidFromSid(sidPtr));
        r["groupname"] = wstringToString(lginfo[i].lgrpi1_name);
        results.push_back(r);
      } else {
        // If LookupAccountNameW failed to find a SID, don't add a row to the
        // table.
        LOG(WARNING)
            << "Failed to find a SID from LookupAccountNameW for group: "
            << lginfo[i].lgrpi1_name;
      }
    }

    // Free the memory allocated by NetLocalGroupEnum:
    if (lginfo != nullptr) {
      NetApiBufferFree(lginfo);
    }
  } while (ret == ERROR_MORE_DATA);
}

QueryData genGroups(QueryContext& context) {
  QueryData results;

  processLocalGroups(results);

  return results;
}
} // namespace tables
} // namespace osquery