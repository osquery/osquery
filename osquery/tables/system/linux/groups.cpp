/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>
#include <set>

#include <grp.h>

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

Mutex grpEnumerationMutex;

QueryData genGroups(QueryContext& context) {
  QueryData results;
  struct group* grp = nullptr;
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

  return results;
}
}
}
