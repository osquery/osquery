/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <cctype>
#include <ctime>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

namespace {

/**
 * @brief Check if a string is a 16-character hex FILETIME
 *
 * On Windows Vista/2008, InstalledOn returns a hex FILETIME string
 * instead of a human-readable date.
 */
bool isHexFiletime(const std::string& s) {
  return s.length() == 16 &&
         std::all_of(s.begin(), s.end(), [](unsigned char c) {
           return std::isxdigit(c);
         });
}

/**
 * @brief Convert a hex FILETIME string to unix timestamp
 *
 * The hex string represents 100-nanosecond intervals since Jan 1, 1601 UTC.
 */
long long hexFiletimeToUnixTime(const std::string& hexStr) {
  auto filetime = tryTo<unsigned long long>(hexStr, 16);
  if (filetime.isError()) {
    return 0;
  }

  FILETIME ft;
  ULARGE_INTEGER uli;
  uli.QuadPart = filetime.get();
  ft.dwHighDateTime = uli.HighPart;
  ft.dwLowDateTime = uli.LowPart;

  return filetimeToUnixtime(ft);
}

/**
 * @brief Try to parse a date string in various formats
 *
 * Common formats seen in InstalledOn:
 * - M/D/YYYY or MM/DD/YYYY (US, with slashes)
 * - YYYY-MM-DD (ISO, with dashes)
 * - D-M-YYYY (some locales, with dashes)
 *
 * Returns unix timestamp or 0 if parsing fails.
 */
long long parseDateString(const std::string& dateStr) {
  if (dateStr.empty()) {
    return 0;
  }

  int a = 0, b = 0, c = 0;
  int year = 0, month = 0, day = 0;

  // Try slash-separated format: M/D/YYYY (US locale, most common)
  if (sscanf(dateStr.c_str(), "%d/%d/%d", &a, &b, &c) == 3) {
    month = a;
    day = b;
    year = c;
  }
  // Try dash-separated format
  else if (sscanf(dateStr.c_str(), "%d-%d-%d", &a, &b, &c) == 3) {
    // If first number looks like a year (>31), assume ISO format YYYY-MM-DD
    if (a > 31) {
      year = a;
      month = b;
      day = c;
    } else {
      // Otherwise assume D-M-YYYY
      day = a;
      month = b;
      year = c;
    }
  } else {
    return 0;
  }

  // Validate parsed values
  if (year >= 1970 && year <= 2100 && month >= 1 && month <= 12 &&
      day >= 1 && day <= 31) {
    struct tm timestamp = {0};
    timestamp.tm_year = year - 1900;
    timestamp.tm_mon = month - 1;
    timestamp.tm_mday = day;
    return static_cast<long long>(_mkgmtime(&timestamp));
  }

  return 0;
}

/**
 * @brief Parse InstalledOn value to unix timestamp
 *
 * Handles both hex FILETIME format (Vista/2008) and date strings.
 */
long long parseInstalledOn(const std::string& installedOn) {
  if (installedOn.empty()) {
    return 0;
  }

  // Check for hex FILETIME format (16 hex characters)
  if (isHexFiletime(installedOn)) {
    return hexFiletimeToUnixTime(installedOn);
  }

  // Try to parse as a date string
  return parseDateString(installedOn);
}

} // namespace

QueryData genInstalledPatches(QueryContext& context) {
  QueryData results;

  const auto wmiSystemReq =
      WmiRequest::CreateWmiRequest("select * from Win32_QuickFixEngineering");

  if (wmiSystemReq && !wmiSystemReq->results().empty()) {
    const auto& wmiResults = wmiSystemReq->results();
    Row r;

    for (const auto& item : wmiResults) {
      item.GetString("CSName", r["csname"]);
      item.GetString("HotFixID", r["hotfix_id"]);
      item.GetString("Caption", r["caption"]);
      item.GetString("Description", r["description"]);
      item.GetString("FixComments", r["fix_comments"]);
      item.GetString("InstalledBy", r["installed_by"]);
      r["install_date"] = "";

      std::string installedOn;
      item.GetString("InstalledOn", installedOn);
      r["installed_on"] = installedOn;

      auto unixTime = parseInstalledOn(installedOn);
      r["installed_on_unix"] = (unixTime > 0) ? BIGINT(unixTime) : "";

      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
