/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <mutex>

#include <osquery/core.h>
#include <osquery/tables.h>

#include <utmpx.h>

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_logged_in_users_defs.hpp>

namespace osquery {
namespace tables {

Mutex utmpxEnumerationMutex;

const std::map<size_t, std::string> kLoginTypes = {
    {EMPTY, "empty"},
    {BOOT_TIME, "boot_time"},
    {NEW_TIME, "new_time"},
    {OLD_TIME, "old_time"},
    {INIT_PROCESS, "init"},
    {LOGIN_PROCESS, "login"},
    {USER_PROCESS, "user"},
    {DEAD_PROCESS, "dead"},
#if !defined(FREEBSD)
    {RUN_LVL, "runlevel"},
    {ACCOUNTING, "accounting"},
#endif
};

QueryData genLoggedInUsers(QueryContext& context) {
  WriteLock lock(utmpxEnumerationMutex);
  QueryData results;
  struct utmpx* entry = nullptr;

  while ((entry = getutxent()) != nullptr) {
    if (entry->ut_pid == 1) {
      continue;
    }
    Row r;
    if (kLoginTypes.count(entry->ut_type) == 0) {
      r["type"] = "unknown";
    } else {
      r["type"] = kLoginTypes.at(entry->ut_type);
    }
    r["user"] = TEXT(entry->ut_user);
    r["tty"] = TEXT(entry->ut_line);
    r["host"] = TEXT(entry->ut_host);
    r["time"] = INTEGER(entry->ut_tv.tv_sec);
    r["pid"] = INTEGER(entry->ut_pid);
    results.push_back(r);
  }
  endutxent();

  return results;
}
}
}
