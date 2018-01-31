/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <vector>
#include <string>

#include <utmpx.h>

#include <osquery/core.h>
#include <osquery/tables.h>

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_last_defs.hpp>

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
