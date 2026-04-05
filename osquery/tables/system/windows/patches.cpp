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

#include <osquery/core/tables.h>
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
    return bigEndianFiletimeToUnixTime(installedOn);
  }

  // Try to parse as a date string
  return parseDateToUnixTime(installedOn);
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
