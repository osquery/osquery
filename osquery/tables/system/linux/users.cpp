/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <pwd.h>

#include <mutex>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

Mutex pwdEnumerationMutex;

void genUser(const struct passwd* pwd, QueryData& results) {
  Row r;
  r["uid"] = BIGINT(pwd->pw_uid);
  r["gid"] = BIGINT(pwd->pw_gid);
  r["uid_signed"] = BIGINT((int32_t)pwd->pw_uid);
  r["gid_signed"] = BIGINT((int32_t)pwd->pw_gid);

  if (pwd->pw_name != nullptr) {
    r["username"] = TEXT(pwd->pw_name);
  }

  if (pwd->pw_gecos != nullptr) {
    r["description"] = TEXT(pwd->pw_gecos);
  }

  if (pwd->pw_dir != nullptr) {
    r["directory"] = TEXT(pwd->pw_dir);
  }

  if (pwd->pw_shell != nullptr) {
    r["shell"] = TEXT(pwd->pw_shell);
  }
  results.push_back(r);
}

QueryData genUsers(QueryContext& context) {
  QueryData results;

  struct passwd* pwd = nullptr;
  if (context.constraints["uid"].exists(EQUALS)) {
    auto uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      long auid{0};
      if (safeStrtol(uid, 10, auid)) {
        WriteLock lock(pwdEnumerationMutex);
        pwd = getpwuid(auid);
        if (pwd != nullptr) {
          genUser(pwd, results);
        }
      }
    }
  } else if (context.constraints["username"].exists(EQUALS)) {
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      WriteLock lock(pwdEnumerationMutex);
      pwd = getpwnam(username.c_str());
      if (pwd != nullptr) {
        genUser(pwd, results);
      }
    }
  } else {
    WriteLock lock(pwdEnumerationMutex);
    pwd = getpwent();
    while (pwd != nullptr) {
      genUser(pwd, results);
      pwd = getpwent();
    }
    endpwent();
  }

  return results;
}

QueryData genStartupItems(QueryContext& context) {
  return QueryData();
}
}
}
