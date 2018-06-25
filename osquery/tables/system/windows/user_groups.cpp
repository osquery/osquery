/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/process_ops.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"
#include "osquery/core/conversions.h"

namespace osquery {

std::string psidToString(PSID sid);
int getGidFromSid(PSID sid);

namespace tables {

void processLocalUserGroups(std::string uid,
                            std::string user,
                            QueryData& results) {
  unsigned long userGroupInfoLevel = 0;
  unsigned long numGroups = 0;
  unsigned long totalUserGroups = 0;
  LOCALGROUP_USERS_INFO_0* ginfo = nullptr;
  PSID sid = nullptr;

  unsigned long ret = 0;

  ret = NetUserGetLocalGroups(nullptr,
                              stringToWstring(user).c_str(),
                              userGroupInfoLevel,
                              1,
                              reinterpret_cast<LPBYTE*>(&ginfo),
                              MAX_PREFERRED_LENGTH,
                              &numGroups,
                              &totalUserGroups);
  if (ret == ERROR_MORE_DATA) {
    LOG(WARNING) << "User " << user
                 << " group membership exceeds buffer limits, processing "
                 << numGroups << " our of " << totalUserGroups << " groups";
  } else if (ret != NERR_Success || ginfo == nullptr) {
    VLOG(1) << " NetUserGetLocalGroups failed for user " << user << " with "
            << ret;
    return;
  }

  for (size_t i = 0; i < numGroups; i++) {
    Row r;
    auto sid = getSidFromUsername(ginfo[i].lgrui0_name);

    r["uid"] = uid;
    r["gid"] = INTEGER(getGidFromSid(static_cast<PSID>(sid.get())));

    results.push_back(r);
  }

  if (ginfo != nullptr) {
    NetApiBufferFree(ginfo);
  }
}

QueryData genUserGroups(QueryContext& context) {
  QueryData results;

  SQL sql(
      "SELECT uid, username FROM users WHERE username NOT IN ('SYSTEM', "
      "'LOCAL SERVICE', 'NETWORK SERVICE')");
  if (!sql.ok()) {
    LOG(WARNING) << sql.getStatus().getMessage();
  }

  for (auto r : sql.rows()) {
    processLocalUserGroups(r["uid"], r["username"], results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
