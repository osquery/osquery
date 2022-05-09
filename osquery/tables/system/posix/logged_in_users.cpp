/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/utils/mutex.h>

#include <utmpx.h>

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

  // switch to the utmp file, and reset to the first entry
  utmpxname(_PATH_UTMPX);
  setutxent();

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
