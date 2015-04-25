/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>

#include <osquery/core.h>
#include <osquery/tables.h>

#include <utmpx.h>

namespace osquery {
namespace tables {

std::mutex utmpxEnumerationMutex;

QueryData genLoggedInUsers(QueryContext& context) {
  std::lock_guard<std::mutex> lock(utmpxEnumerationMutex);
  QueryData results;
  struct utmpx* entry = nullptr;

  while ((entry = getutxent()) != nullptr) {
    if (entry->ut_pid == 1) {
      continue;
    }
    Row r;
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
