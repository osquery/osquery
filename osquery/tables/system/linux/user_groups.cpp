/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/system/user_groups.h"

namespace osquery {
namespace tables {

extern std::mutex pwdEnumerationMutex;

QueryData genUserGroups(QueryContext &context) {
  QueryData results;
  struct passwd *pwd = nullptr;

  // TODO(1160):  Add exists uid EQUALS constraint
  if (context.constraints["uid"].exists()) {
    std::set<std::string> uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto &uid : uids) {
      pwd = getpwuid(std::strtol(uid.c_str(), NULL, 10));
      if (pwd != nullptr) {
        user_t<uid_t, gid_t> user;
        user.name = pwd->pw_name;
        user.uid = pwd->pw_uid;
        user.gid = pwd->pw_gid;
        getGroupsForUser<uid_t, gid_t>(results, user);
      }
    }
  } else {
    std::lock_guard<std::mutex> lock(pwdEnumerationMutex);
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
