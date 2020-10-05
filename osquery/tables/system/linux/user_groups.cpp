/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/user_groups.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/mutex.h>

namespace osquery {
namespace tables {

extern Mutex pwdEnumerationMutex;

QueryData genUserGroups(QueryContext& context) {
  QueryData results;
  struct passwd* pwd = nullptr;

  if (context.constraints["uid"].exists(EQUALS)) {
    std::set<std::string> uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      auto const auid_exp = tryTo<long>(uid, 10);
      if (auid_exp.isValue() && (pwd = getpwuid(auid_exp.get())) != nullptr) {
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
