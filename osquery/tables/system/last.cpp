// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <utmpx.h>

#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genLastAccess() {
  QueryData results;
  struct utmpx *ut;
#ifdef __APPLE__
  setutxent_wtmp(0); // 0 = reverse chronological order

  while ((ut = getutxent_wtmp()) != NULL) {
#else

#ifndef __FreeBSD__
  utmpxname("/var/log/wtmpx");
#endif
  setutxent();

  while ((ut = getutxent()) != NULL) {
#endif

    Row r;
    r["username"] = TEXT(ut->ut_user);
    r["tty"] = TEXT(ut->ut_line);
    r["pid"] = INTEGER(ut->ut_pid);
    r["type"] = INTEGER(ut->ut_type);
    r["time"] = INTEGER(ut->ut_tv.tv_sec);
    r["host"] = TEXT(ut->ut_host);

    results.push_back(r);
  }

#ifdef __APPLE__
  endutxent_wtmp();
#else
  endutxent();
#endif

  return results;
}
}
}
