/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tables.h>

#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

#include <osquery/core/windows/wmi.h>

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  Row r;
  std::string version_string;

  const std::string kWmiQuery =
      "SELECT CAPTION,VERSION,INSTALLDATE,OSARCHITECTURE FROM "
      "Win32_OperatingSystem";

  const WmiRequest wmiRequest(kWmiQuery);
  const std::vector<WmiResultItem>& wmiResults = wmiRequest.results();

  if (wmiResults.empty()) {
    return {};
  }

  wmiResults[0].GetString("InstallDate", r["install_date"]);
  std::string osName;
  wmiResults[0].GetString("Caption", osName);
  r["name"] = osName;
  r["codename"] = osName;
  wmiResults[0].GetString("Version", version_string);
  auto version = osquery::split(version_string, ".");

  switch (version.size()) {
  case 3:
    r["build"] = SQL_TEXT(version[2]);
  case 2:
    r["minor"] = INTEGER(version[1]);
  case 1:
    r["major"] = INTEGER(version[0]);
    break;
  default:
    break;
  }

  wmiResults[0].GetString("OSArchitecture", r["arch"]);

  r["platform"] = "windows";
  r["platform_like"] = "windows";
  r["version"] = r["major"] + "." + r["minor"] + "." + r["build"];

  return {r};
}
} // namespace tables
} // namespace osquery
