// Copyright 2004-present Wesley Shields <wxs@atarininja.org>.
// All Rights Reserved.

#include <set>
#include <mutex>
#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

#include <utmpx.h>

namespace osquery {
namespace tables {

std::mutex utmpxEnumerationMutex;

QueryData genLoggedInUsers() {
  std::lock_guard<std::mutex> lock(utmpxEnumerationMutex);
  QueryData results;
  struct utmpx *entry = nullptr;

  while ((entry = getutxent()) != NULL) {
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
