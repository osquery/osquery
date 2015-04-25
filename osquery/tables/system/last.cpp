/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <string>

#include <utmpx.h>

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genLastAccess(QueryContext& context) {
  QueryData results;
  struct utmpx* ut;
#ifdef __APPLE__
  setutxent_wtmp(0); // 0 = reverse chronological order

  while ((ut = getutxent_wtmp()) != nullptr) {
#else

#ifndef __FreeBSD__
  utmpxname("/var/log/wtmpx");
#endif
  setutxent();

  while ((ut = getutxent()) != nullptr) {
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
