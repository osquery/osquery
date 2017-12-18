/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <vector>
#include <string>

#include <grp.h>
#include <pwd.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#define EXPECTED_GROUPS_MAX 64

#ifdef __APPLE__
// This symbol is exported from libSystem.B and has been since 10.6.
extern "C" int getgroupcount(const char *name, gid_t basegid);
#endif

namespace osquery {
namespace tables {

template <typename T>
static inline void addGroupsToResults(QueryData &results,
                                      int uid,
                                      const T *groups,
                                      int ngroups) {
  for (int i = 0; i < ngroups; i++) {
    Row r;
    r["uid"] = BIGINT(uid);
    r["gid"] = BIGINT(groups[i]);
    results.push_back(r);
  }

  return;
}

template <typename uid_type, typename gid_type>
struct user_t {
  const char *name;
  uid_type uid;
  gid_type gid;
};

template <typename uid_type, typename gid_type>
static void getGroupsForUser(QueryData &results,
                             const user_t<uid_type, gid_type> &user) {
#ifdef __APPLE__
  int ngroups = getgroupcount(user.name, user.gid);
  gid_type *groups = new gid_type[ngroups];
  if (getgrouplist(user.name, user.gid, groups, &ngroups) < 0) {
    TLOG << "Could not get users group list";
  } else {
    addGroupsToResults(results, user.uid, groups, ngroups);
  }
  delete[] groups;
#else
  gid_type groups_buf[EXPECTED_GROUPS_MAX];
  gid_type *groups = groups_buf;
  int ngroups = EXPECTED_GROUPS_MAX;

  // GLIBC version before 2.3.3 may have a buffer overrun:
  // http://man7.org/linux/man-pages/man3/getgrouplist.3.html
  if (getgrouplist(user.name, user.gid, groups, &ngroups) < 0) {
    // EXPECTED_GROUPS_MAX was probably not large enough.
    // Try a larger size buffer.
    groups = new gid_type[ngroups];
    if (groups == nullptr) {
      TLOG << "Could not allocate memory to get user groups";
      return;
    }

    if (getgrouplist(user.name, user.gid, groups, &ngroups) < 0) {
      TLOG << "Could not get users group list";
    } else {
      addGroupsToResults(results, user.uid, groups, ngroups);
    }

    delete[] groups;
  } else {
    addGroupsToResults(results, user.uid, groups, ngroups);
  }
#endif

  return;
}
}
}
