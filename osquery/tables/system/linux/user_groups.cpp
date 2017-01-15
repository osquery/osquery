/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/system/user_groups.h"
#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

extern Mutex pwdEnumerationMutex;

QueryData genUserGroups(QueryContext& context) {
  QueryData results;
  struct passwd* pwd = nullptr;

  if (context.constraints["uid"].exists(EQUALS)) {
    std::set<std::string> uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      long auid{0};
      if (safeStrtol(uid, 10, auid) && (pwd = getpwuid(auid)) != nullptr) {
        user_t<uid_t, gid_t> user;
        user.name = pwd->pw_name;
        user.uid = pwd->pw_uid;
        user.gid = pwd->pw_gid;
        getGroupsForUser<uid_t, gid_t>(results, user);
      }
    }
  } else {
    WriteLock lock(pwdEnumerationMutex);
    std::set<gid_t> users_in;
    while ((pwd = getpwent()) != nullptr) {
      if (std::find(users_in.begin(), users_in.end(), pwd->pw_uid) ==
          users_in.end()) {
        user_t<uid_t, gid_t> user;
        user.name = pwd->pw_name;
        user.uid = pwd->pw_uid;
        user.gid = pwd->pw_gid;
        getGroupsForUser<uid_t, gid_t>(results, user);
        users_in.insert(pwd->pw_uid);
      }
    }
    endpwent();
    users_in.clear();
  }

  return results;
}
}
}
