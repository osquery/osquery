/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <ctime>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/system.h>
#include <osquery/tables.h>

namespace osquery {

DECLARE_bool(utc);

namespace tables {

QueryData genTime(QueryContext& context) {
  Row r;
  time_t local_time = getUnixTime();
  auto osquery_time = getUnixTime();
  auto osquery_timestamp = getAsciiTime();

  // The concept of 'now' is configurable.
  struct tm gmt;
  gmtime_r(&local_time, &gmt);

  struct tm now;
  if (FLAGS_utc) {
    now = gmt;
  } else {
    localtime_r(&local_time, &now);
  }

  struct tm local;
  localtime_r(&local_time, &local);
  local_time = std::mktime(&local);

  char weekday[10] = {0};
  strftime(weekday, sizeof(weekday), "%A", &now);

  char timezone[5] = {0};
  strftime(timezone, sizeof(timezone), "%Z", &now);

  char local_timezone[5] = {0};
  strftime(local_timezone, sizeof(local_timezone), "%Z", &local);

  char iso_8601[21] = {0};
  strftime(iso_8601, sizeof(iso_8601), "%FT%TZ", &gmt);

  r["weekday"] = SQL_TEXT(weekday);
  r["year"] = INTEGER(now.tm_year + 1900);
  r["month"] = INTEGER(now.tm_mon + 1);
  r["day"] = INTEGER(now.tm_mday);
  r["hour"] = INTEGER(now.tm_hour);
  r["minutes"] = INTEGER(now.tm_min);
  r["seconds"] = INTEGER(now.tm_sec);
  r["timezone"] = SQL_TEXT(timezone);
  if (r["timezone"].empty()) {
    r["timezone"] = "UTC";
  }

  r["local_time"] = INTEGER(local_time);
  r["local_timezone"] = SQL_TEXT(local_timezone);
  if (r["local_timezone"].empty()) {
    r["local_timezone"] = "UTC";
  }

  r["unix_time"] = INTEGER(osquery_time);
  r["timestamp"] = SQL_TEXT(osquery_timestamp);
  // Date time is provided in ISO 8601 format, then duplicated in iso_8601.
  r["datetime"] = SQL_TEXT(iso_8601);
  r["iso_8601"] = SQL_TEXT(iso_8601);

  QueryData results;
  results.push_back(r);
  return results;
}
}
}
