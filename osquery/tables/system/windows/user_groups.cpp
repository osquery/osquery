/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <LM.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include "osquery/tables/system/windows/registry.h"
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/process/process.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

namespace tables {

void processLocalUserGroups(const User& user,
                            const GroupsCache& groups_cache,
                            QueryData& results) {
  DWORD group_info_level = 0;
  DWORD num_groups = 0;
  DWORD total_groups = 0;
  LOCALGROUP_USERS_INFO_0* group_info = nullptr;

  DWORD ret = 0;

  std::wstring username = stringToWstring(user.username);

  ret = NetUserGetLocalGroups(nullptr,
                              username.c_str(),
                              group_info_level,
                              1,
                              reinterpret_cast<LPBYTE*>(&group_info),
                              MAX_PREFERRED_LENGTH,
                              &num_groups,
                              &total_groups);
  if (ret == ERROR_MORE_DATA) {
    LOG(WARNING) << "User " << user.username
                 << " group membership exceeds buffer limits, processing "
                 << num_groups << " our of " << total_groups << " groups";
  } else if (ret != NERR_Success || group_info == nullptr) {
    VLOG(1) << " NetUserGetLocalGroups failed for user " << user.username
            << " with " << ret;
    return;
  }

  for (std::size_t i = 0; i < num_groups; i++) {
    std::string groupname = wstringToString(group_info[i].lgrui0_name);

    auto opt_group = groups_cache.getGroupByName(groupname);

    if (!opt_group.has_value()) {
      continue;
    }

    Row r;

    r["uid"] = INTEGER(user.uid);
    r["gid"] = INTEGER(opt_group->gid);

    results.push_back(std::move(r));
  }

  if (group_info != nullptr) {
    NetApiBufferFree(group_info);
  }
}

QueryData genUserGroups(QueryContext& context) {
  QueryData results;

  auto uid_it = context.constraints.find("uid");
  std::set<std::string> selected_uids;

  if (uid_it != context.constraints.end()) {
    selected_uids = uid_it->second.getAll(EQUALS);
  }

  const auto& users_cache = GlobalUsersGroupsCache::getUsersCache();
  const auto& groups_cache = GlobalUsersGroupsCache::getGroupsCache();

  if (!selected_uids.empty()) {
    for (const auto selected_uid_str : selected_uids) {
      auto selected_uid_res = tryTo<std::uint32_t>(selected_uid_str);

      if (selected_uid_res.isError()) {
        continue;
      }

      auto users = users_cache.getUsersByUid(selected_uid_res.take());

      for (const auto& user : users) {
        processLocalUserGroups(user, groups_cache, results);
      }
    }
  } else {
    const auto users = users_cache.getAllUsers();
    for (const auto& user : users) {
      if (user.username == "LOCAL SERVICE" || user.username == "SYSTEM" ||
          user.username == "NETWORK SERVICE") {
        continue;
      }
      processLocalUserGroups(user, groups_cache, results);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
