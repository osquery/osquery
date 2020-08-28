/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <pwd.h>

#include <mutex>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/mutex.h>

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
      auto const auid_exp = tryTo<long>(uid, 10);
      if (auid_exp.isValue()) {
        WriteLock lock(pwdEnumerationMutex);
        pwd = getpwuid(auid_exp.get());
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
}
}
