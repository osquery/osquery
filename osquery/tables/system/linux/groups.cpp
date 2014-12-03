// Copyright 2004-present Facebook. All Rights Reserved.

#include <set>
#include <mutex>

#include <grp.h>

#include "osquery/core.h"
#include "osquery/tables.h"

namespace osquery {
namespace tables {

std::mutex grpEnumerationMutex;

QueryData genGroups(QueryContext &context) {
  std::lock_guard<std::mutex> lock(grpEnumerationMutex);
  QueryData results;
  struct group *grp = nullptr;
  std::set<long> groups_in;

  setgrent();
  while ((grp = getgrent()) != NULL) {
    if (std::find(groups_in.begin(), groups_in.end(), grp->gr_gid) ==
        groups_in.end()) {
      Row r;
      r["gid"] = INTEGER(grp->gr_gid);
      r["gid_signed"] = INTEGER((int32_t) grp->gr_gid);
      r["groupname"] = TEXT(grp->gr_name);
      results.push_back(r);
      groups_in.insert(grp->gr_gid);
    }
  }
  endgrent();
  groups_in.clear();

  return results;
}
}
}
