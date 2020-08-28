/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <sstream>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

std::string to_iso8601_date(const FILETIME& ft) {
  SYSTEMTIME date = {0};

  if (FileTimeToSystemTime(&ft, &date) == FALSE) {
    return "";
  }

  std::ostringstream iso_date;
  iso_date << std::setfill('0');
  iso_date << std::setw(4) << date.wYear << "-" << std::setw(2) << date.wMonth
           << "-" << std::setw(2) << date.wDay;

  return iso_date.str();
}

QueryData genPlatformInfo(QueryContext& context) {
  QueryData results;

  std::string query =
      "select Manufacturer, SMBIOSBIOSVersion, ReleaseDate, "
      "SystemBiosMajorVersion, SystemBiosMinorVersion from Win32_BIOS";
  const WmiRequest request(query);
  if (!request.getStatus().ok()) {
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = request.results();
  if (wmiResults.size() != 1) {
    return results;
  }
  Row r;
  std::string sPlaceholder;
  wmiResults[0].GetString("Manufacturer", r["vendor"]);
  wmiResults[0].GetString("SMBIOSBIOSVersion", r["version"]);
  unsigned char majorRevision = 0x0;
  wmiResults[0].GetUChar("SystemBiosMajorVersion", majorRevision);
  unsigned char minorRevision = 0x0;
  wmiResults[0].GetUChar("SystemBiosMinorVersion", minorRevision);
  r["revision"] =
      std::to_string(majorRevision) + "." + std::to_string(minorRevision);

  FILETIME release_date = {0};
  wmiResults[0].GetDateTime("ReleaseDate", false, release_date);

  auto s = to_iso8601_date(release_date);
  r["date"] = s.empty() ? "-1" : s;

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
