/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

#if defined(__APPLE__)
#include <errno.h>
#include <sys/sysctl.h>
#include <time.h>
#elif defined(__linux__)
#include <sys/sysinfo.h>
#elif defined(WIN32)
#include <windows.h>
#endif

#define DECLARE_TABLE_IMPLEMENTATION_uptime
#include <generated/tables/tbl_uptime_defs.hpp>

namespace osquery {
namespace tables {

long getUptime() {
#if defined(DARWIN)
  struct timeval boot_time;
  size_t len = sizeof(boot_time);
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};

  if (sysctl(mib, 2, &boot_time, &len, nullptr, 0) < 0) {
    return -1;
  }

  time_t seconds_since_boot = boot_time.tv_sec;
  time_t current_seconds = time(nullptr);

  return long(difftime(current_seconds, seconds_since_boot));
#elif defined(__linux__)
  struct sysinfo sys_info;

  if (sysinfo(&sys_info) != 0) {
    return -1;
  }

  return sys_info.uptime;
#elif defined(WIN32)
  return static_cast<long>(GetTickCount64() / 1000);
#endif

  return -1;
}

QueryData genUptime(QueryContext& context) {
  Row r;
  QueryData results;
  long uptime_in_seconds = getUptime();

  if (uptime_in_seconds >= 0) {
    r["days"] = INTEGER(uptime_in_seconds / 60 / 60 / 24);
    r["hours"] = INTEGER((uptime_in_seconds / 60 / 60) % 24);
    r["minutes"] = INTEGER((uptime_in_seconds / 60) % 60);
    r["seconds"] = INTEGER(uptime_in_seconds % 60);
    r["total_seconds"] = BIGINT(uptime_in_seconds);
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
