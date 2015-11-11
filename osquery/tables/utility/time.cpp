/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ctime>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genTime(QueryContext& context) {
  Row r;
  time_t _time = time(nullptr);
  struct tm* now = localtime(&_time);
  struct tm* gmt = gmtime(&_time);

  char weekday[10] = {0};
  strftime(weekday, sizeof(weekday), "%A", now);

  char timezone[5] = {0};
  strftime(timezone, sizeof(timezone), "%Z", now);

  std::string timestamp;
  timestamp = asctime(gmt);
  boost::algorithm::trim(timestamp);
  timestamp += " UTC";

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
  r["unix_time"] = INTEGER(_time);
  r["timestamp"] = TEXT(timestamp);
  r["iso_8601"] = TEXT(iso_8601);

  QueryData results;
  results.push_back(r);
  return results;
}
}
}
