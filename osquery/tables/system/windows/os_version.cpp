/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  Row r;
  std::string version_string;

  const std::string kWmiQuery =
      "SELECT CAPTION,VERSION,INSTALLDATE,OSARCHITECTURE FROM "
      "Win32_OperatingSystem";

  const auto wmiRequest = WmiRequest::CreateWmiRequest(kWmiQuery);

  if (!wmiRequest) {
    LOG(WARNING) << wmiRequest.getError().getMessage();
    return {};
  }

  const std::vector<WmiResultItem>& wmiResults = wmiRequest->results();

  if (wmiResults.empty()) {
    return {};
  }

  std::string osName;
  wmiResults[0].GetString("Caption", osName);
  r["name"] = osName;
  r["codename"] = osName;

  std::string cimInstallDate{""};
  wmiResults[0].GetString("InstallDate", cimInstallDate);
  r["install_date"] = BIGINT(cimDatetimeToUnixtime(cimInstallDate));

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
