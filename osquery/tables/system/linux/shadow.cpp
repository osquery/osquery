/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mutex>
#include <regex>

#include <shadow.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/utils/mutex.h>

namespace osquery {
namespace tables {

const auto kPasswordHashAlgRegex = std::regex("^\\$(\\w+)\\$");

void genShadowForAccount(const struct spwd* spwd, QueryData& results) {
  Row r;
  r["last_change"] = BIGINT(spwd->sp_lstchg);
  r["min"] = BIGINT(spwd->sp_min);
  r["max"] = BIGINT(spwd->sp_max);
  r["warning"] = BIGINT(spwd->sp_warn);
  r["inactive"] = BIGINT(spwd->sp_inact);
  r["expire"] = BIGINT(spwd->sp_expire);
  r["flag"] = BIGINT(spwd->sp_flag);

  r["username"] = spwd->sp_namp != nullptr ? TEXT(spwd->sp_namp) : "";

  if (spwd->sp_pwdp != nullptr) {
    std::string password = std::string(spwd->sp_pwdp);
    std::smatch matches;
    if (password == "!!") {
      r["password_status"] = "not_set";
    } else if (password[0] == '!' || password[0] == '*' || password[0] == 'x') {
      r["password_status"] = "locked";
    } else if (password.empty()) {
      r["password_status"] = "empty";
    } else {
      r["password_status"] = "active";
    }
    if (std::regex_search(password, matches, kPasswordHashAlgRegex)) {
      r["hash_alg"] = std::string(matches[1]);
    }
  } else {
    r["password_status"] = "empty";
  }
  results.push_back(r);
}

QueryData genShadow(QueryContext& context) {
  QueryData results;
  Mutex spwdEnumerationMutex;

  struct spwd* spwd = nullptr;
  if (context.constraints["username"].exists(EQUALS)) {
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      WriteLock lock(spwdEnumerationMutex);
      spwd = getspnam(username.c_str());
      if (spwd != nullptr) {
        genShadowForAccount(spwd, results);
      }
    }
  } else {
    WriteLock lock(spwdEnumerationMutex);
    spwd = getspent();
    while (spwd != nullptr) {
      genShadowForAccount(spwd, results);
      spwd = getspent();
    }
    endspent();
  }

  return results;
}
}
}
