/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>

#include <grp.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

void setGroupRow(Row& r, const group* grp) {
  r["groupname"] = TEXT(grp->gr_name);
  r["gid"] = INTEGER(grp->gr_gid);
  r["gid_signed"] = INTEGER((int32_t)grp->gr_gid);
  r["pid_with_namespace"] = "0";
}

QueryData genGroupsImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  struct group* grp_result{nullptr};
  struct group grp;

  size_t bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
  if (bufsize > 16384) { /* Value was indeterminate */
    bufsize = 16384; /* Should be more than enough */
  }
  auto buf = std::make_unique<char[]>(bufsize);
  if (context.constraints["gid"].exists(EQUALS)) {
    auto gids = context.constraints["gid"].getAll<long long>(EQUALS);
    for (const auto& gid : gids) {
      getgrgid_r(gid, &grp, buf.get(), bufsize, &grp_result);
      if (grp_result == nullptr) {
        continue;
      }

      Row r;
      setGroupRow(r, grp_result);
      results.push_back(r);
    }
  } else {
    std::set<long> groups_in;
    setgrent();
    while (1) {
      getgrent_r(&grp, buf.get(), bufsize, &grp_result);
      if (grp_result == nullptr) {
        break;
      }
      if (std::find(groups_in.begin(), groups_in.end(), grp_result->gr_gid) ==
          groups_in.end()) {
        Row r;
        setGroupRow(r, grp_result);
        results.push_back(r);
        groups_in.insert(grp_result->gr_gid);
      }
    }
    endgrent();
    groups_in.clear();
  }

  return results;
}

QueryData genGroups(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "groups", genGroupsImpl);
  } else {
    GLOGLogger logger;
    return genGroupsImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
