/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>

#include <boost/algorithm/string/trim.hpp>

#ifdef WIN32
#include <osquery/utils/conversions/windows/strings.h>
#endif

#include <osquery/logger/logger.h>
#include <osquery/utils/system/time.h>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>

namespace osquery {

namespace tables {

QueryData genTime(QueryContext& context) {
  Row r;

  time_t osquery_time = getUnixTime();

  struct tm gmt;
  gmtime_r(&osquery_time, &gmt);
  struct tm now = gmt;
  auto osquery_timestamp = toAsciiTime(&now);

  std::string local_timezone;

  {
#ifdef WIN32
    TIME_ZONE_INFORMATION time_zone_information{};
    if (GetTimeZoneInformation(&time_zone_information) ==
        TIME_ZONE_ID_INVALID) {
      LOG(ERROR) << "Failed to acquire the time";
    } else {
      local_timezone = wstringToString(time_zone_information.StandardName);
    }

#else
    struct tm local {};
    localtime_r(&osquery_time, &local);

    std::array<char, 5> buffer;
    strftime(buffer.data(), buffer.size(), "%Z", &local);

    local_timezone.assign(buffer.data());
#endif
  }

  char weekday[10] = {0};
  strftime(weekday, sizeof(weekday), "%A", &now);

  char timezone[5] = {0};
  strftime(timezone, sizeof(timezone), "%Z", &now);


  char iso_8601[21] = {0};
  strftime(iso_8601, sizeof(iso_8601), "%FT%TZ", &gmt);
#ifdef WIN32
  if (context.isColumnUsed("win_timestamp")) {
    FILETIME ft = {0};
    GetSystemTimeAsFileTime(&ft);
    LARGE_INTEGER li = {0};
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    long long int hns = li.QuadPart;
    r["win_timestamp"] = BIGINT(hns);
  }
#endif
  r["weekday"] = SQL_TEXT(weekday);
  r["year"] = INTEGER(now.tm_year + 1900);
  r["month"] = INTEGER(now.tm_mon + 1);
  r["day"] = INTEGER(now.tm_mday);
  r["hour"] = INTEGER(now.tm_hour);
  r["minutes"] = INTEGER(now.tm_min);
  r["seconds"] = INTEGER(now.tm_sec);
  r["timezone"] = "UTC";

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
} // namespace tables
} // namespace osquery
