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
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/time.h>

namespace osquery {

namespace tables {

Row genGroup(const Group& group) {
  Row r;
  r["gid"] = BIGINT(group.gid);
  r["gid_signed"] = INTEGER(group.gid);
  r["group_sid"] = group.sid;
  r["comment"] = group.comment;
  r["groupname"] = group.groupname;

  return r;
}

QueryData genGroups(QueryContext& context) {
  auto gid_it = context.constraints.find("gid");
  auto sid_it = context.constraints.find("group_sid");
  std::set<std::string> selected_sids;
  std::set<std::string> selected_gids;

  if (sid_it != context.constraints.end()) {
    selected_sids = sid_it->second.getAll(EQUALS);
  }

  if (selected_sids.empty() && gid_it != context.constraints.end()) {
    selected_gids = gid_it->second.getAll(EQUALS);
  }

  QueryData results;
  const auto& groups_cache = GlobalUsersGroupsCache::getGroupsCache();

  if (!selected_sids.empty()) {
    for (const auto& selected_sid : selected_sids) {
      auto opt_group = groups_cache.getGroupBySid(selected_sid);

      if (!opt_group.has_value()) {
        continue;
      }

      auto group_row = genGroup(std::move(*opt_group));
      results.emplace_back(std::move(group_row));
    }

  } else if (!selected_gids.empty()) {
    auto selected_gids = gid_it->second.getAll(EQUALS);

    for (const auto& selected_gid_str : selected_gids) {
      auto selected_gid_res = tryTo<std::uint32_t>(selected_gid_str);

      if (selected_gid_res.isError()) {
        continue;
      }

      auto groups = groups_cache.getGroupsByGid(selected_gid_res.take());

      for (auto& group : groups) {
        auto group_row = genGroup(std::move(group));
        results.emplace_back(std::move(group_row));
      }
    }
  } else {
    auto groups = groups_cache.getAllGroups();

    for (const auto& group : groups) {
      auto group_row = genGroup(std::move(group));
      results.emplace_back(std::move(group_row));
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
