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
#include <osquery/utils/mutex.h>

namespace osquery {
namespace tables {

Mutex grpEnumerationMutex;

QueryData genGroups(QueryContext& context) {
  QueryData results;
  struct group* grp = nullptr;

  if (context.constraints["gid"].exists(EQUALS)) {
    auto gids = context.constraints["gid"].getAll<long long>(EQUALS);
    for (const auto& gid : gids) {
      Row r;
      grp = getgrgid(gid);
      r["gid"] = BIGINT(gid);
      if (grp != nullptr) {
        r["gid_signed"] = INTEGER((int32_t)grp->gr_gid);
        r["groupname"] = TEXT(grp->gr_name);
      }
      results.push_back(r);
    }
  } else {
    std::set<long> groups_in;
    WriteLock lock(grpEnumerationMutex);
    setgrent();
    while ((grp = getgrent()) != nullptr) {
      if (std::find(groups_in.begin(), groups_in.end(), grp->gr_gid) ==
          groups_in.end()) {
        Row r;
        r["gid"] = INTEGER(grp->gr_gid);
        r["gid_signed"] = INTEGER((int32_t)grp->gr_gid);
        r["groupname"] = TEXT(grp->gr_name);
        results.push_back(r);
        groups_in.insert(grp->gr_gid);
      }
    }
    endgrent();
    groups_in.clear();
  }

  return results;
}
}
}
