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

#include "osquery/tables/system/windows/registry.h"
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/process/process.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/time.h>

namespace osquery {

const std::string kRegProfilePath =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows "
    "NT\\CurrentVersion\\ProfileList";

namespace tables {

std::string getUserShell(const std::string& sid) {
  // TODO: This column exists for cross-platform consistency, but
  // the answer on Windows is arbitrary. %COMSPEC% env variable may
  // be the best answer. Currently, hard-coded.
  return "C:\\Windows\\system32\\cmd.exe";
}

Row genUser(const User& user) {
  Row r;
  r["username"] = user.username;
  r["uid"] = BIGINT(user.uid);
  r["gid"] = BIGINT(user.gid);
  r["uid_signed"] = INTEGER(static_cast<std::int32_t>(user.uid));
  r["gid_signed"] = INTEGER(static_cast<std::int32_t>(user.gid));
  r["description"] = user.description;
  r["directory"] = user.directory;
  r["shell"] = getUserShell(user.sid);
  r["type"] = user.type;
  r["uuid"] = user.sid;
  return r;
}

QueryData genUsers(QueryContext& context) {
  auto uid_it = context.constraints.find("uid");
  auto sid_it = context.constraints.find("uuid");
  std::set<std::string> selected_sids;
  std::set<std::string> selected_uids;

  if (sid_it != context.constraints.end()) {
    selected_sids = sid_it->second.getAll(EQUALS);
  }

  if (selected_sids.empty() && uid_it != context.constraints.end()) {
    selected_uids = uid_it->second.getAll(EQUALS);
  }

  QueryData results;
  auto& users_cache = GlobalUsersGroupsCache::getUsersCache();

  if (!selected_sids.empty()) {
    for (const auto& selected_sid : selected_sids) {
      auto opt_user = users_cache.getUserBySid(selected_sid);

      if (!opt_user.has_value()) {
        continue;
      }

      auto user_row = genUser(*opt_user);
      results.emplace_back(std::move(user_row));
    }

  } else if (!selected_uids.empty()) {
    auto selected_uids = uid_it->second.getAll(EQUALS);

    for (const auto& selected_uid_str : selected_uids) {
      auto selected_uid_res = tryTo<std::uint32_t>(selected_uid_str);

      if (selected_uid_res.isError()) {
        continue;
      }

      auto users = users_cache.getUsersByUid(selected_uid_res.take());

      for (const auto& user : users) {
        auto user_row = genUser(user);
        results.emplace_back(std::move(user_row));
      }
    }
  } else {
    auto users = users_cache.getAllUsers();

    for (const auto& user : users) {
      auto user_row = genUser(user);
      results.emplace_back(std::move(user_row));
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
