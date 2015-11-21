/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>
#include <mutex>
#include <vector>
#include <string>

#include <pwd.h>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

std::mutex pwdEnumerationMutex;

void genUser(const struct passwd* pwd, QueryData& results) {
  Row r;
  r["uid"] = BIGINT(pwd->pw_uid);
  r["gid"] = BIGINT(pwd->pw_gid);
  r["uid_signed"] = BIGINT((int32_t)pwd->pw_uid);
  r["gid_signed"] = BIGINT((int32_t)pwd->pw_gid);
  r["username"] = TEXT(pwd->pw_name);
  r["description"] = TEXT(pwd->pw_gecos);
  r["directory"] = TEXT(pwd->pw_dir);
  r["shell"] = TEXT(pwd->pw_shell);
  results.push_back(r);
}

QueryData genUsers(QueryContext& context) {
  QueryData results;
  struct passwd *pwd = nullptr;

  if (context.constraints["uid"].exists(EQUALS)) {
    std::set<std::string> uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      long auid{0};
      if (safeStrtol(uid, 10, auid) && (pwd = getpwuid(auid)) != nullptr) {
        genUser(pwd, results);
      }
    }
  } else {
    std::lock_guard<std::mutex> lock(pwdEnumerationMutex);
    while ((pwd = getpwent()) != nullptr) {
      genUser(pwd, results);
    }
    endpwent();
  }

  return results;
}
}
}
