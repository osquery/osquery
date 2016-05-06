/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ctime>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/tables.h>

namespace osquery {

DECLARE_bool(utc);

namespace tables {

QueryData genTime(QueryContext& context) {
  Row r;
  // Request UNIX time (a wrapper around std::time).
  auto local_time = std::time(nullptr);
  auto osquery_time = getUnixTime();
  auto osquery_timestamp = getAsciiTime();

  // The concept of 'now' is configurable.
  struct tm* gmt = std::gmtime(&local_time);
  struct tm* now = (FLAGS_utc) ? gmt : std::localtime(&local_time);
  struct tm* local = std::localtime(&local_time);

  char weekday[10] = {0};
  strftime(weekday, sizeof(weekday), "%A", now);

  char timezone[5] = {0};
  strftime(timezone, sizeof(timezone), "%Z", now);

  char local_timezone[5] = {0};
  strftime(local_timezone, sizeof(local_timezone), "%Z", local);

  char iso_8601[21] = {0};
  strftime(iso_8601, sizeof(iso_8601), "%FT%TZ", gmt);

  r["weekday"] = TEXT(weekday);
  r["year"] = INTEGER(now->tm_year + 1900);
  r["month"] = INTEGER(now->tm_mon + 1);
  r["day"] = INTEGER(now->tm_mday);
  r["hour"] = INTEGER(now->tm_hour);
  r["minutes"] = INTEGER(now->tm_min);
  r["seconds"] = INTEGER(now->tm_sec);
  r["timezone"] = TEXT(timezone);
  r["local_time"] = INTEGER(local_time);
  r["local_timezone"] = TEXT(local_timezone);
  r["unix_time"] = INTEGER(osquery_time);
  r["timestamp"] = TEXT(osquery_timestamp);
  // Date time is provided in ISO 8601 format, then duplicated in iso_8601.
  r["datetime"] = TEXT(iso_8601);
  r["iso_8601"] = TEXT(iso_8601);

  QueryData results;
  results.push_back(r);
  return results;
}
}
}
