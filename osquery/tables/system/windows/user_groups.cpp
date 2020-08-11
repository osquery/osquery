/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include "osquery/tables/system/windows/registry.h"
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/process/process.h>
#include <osquery/process/windows/process_ops.h>

namespace osquery {

std::string psidToString(PSID sid);
uint32_t getGidFromSid(PSID sid);

namespace tables {

void processLocalUserGroups(std::string uid,
                            std::string user,
                            QueryData& results) {
  unsigned long userGroupInfoLevel = 0;
  unsigned long numGroups = 0;
  unsigned long totalUserGroups = 0;
  LOCALGROUP_USERS_INFO_0* ginfo = nullptr;

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
    r["gid"] = BIGINT(getGidFromSid(static_cast<PSID>(sid.get())));

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
