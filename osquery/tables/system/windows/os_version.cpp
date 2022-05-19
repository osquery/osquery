/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

const std::string osCurrentVersionKey =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

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
    std::string productNameQuery = "SELECT data FROM registry WHERE path = \"" +
                                   osCurrentVersionKey + "\\ProductName\"";
    SQL productNameResults(productNameQuery);
    if (!productNameResults.rows().empty()) {
      r["name"] = productNameResults.rows()[0].at("data");
      r["codename"] = productNameResults.rows()[0].at("data");
    }

    std::string installDateQuery = "SELECT data FROM registry WHERE path = \"" +
                                   osCurrentVersionKey + "\\InstallDate\"";
    SQL installDateResults(installDateQuery);
    if (!installDateResults.rows().empty()) {
      r["install_date"] = installDateResults.rows()[0].at("data");
    }

    bool separateVersionkeys = true;
    std::string majorVerQuery = "SELECT data FROM registry WHERE path = \"" +
                                osCurrentVersionKey +
                                "\\CurrentMajorVersionNumber\"";
    SQL majorVerResults(majorVerQuery);
    if (!majorVerResults.rows().empty()) {
      r["major"] = majorVerResults.rows()[0].at("data");
    } else {
      separateVersionkeys = false;
    }

    std::string minorVerQuery = "SELECT data FROM registry WHERE path = \"" +
                                osCurrentVersionKey +
                                "\\CurrentMinorVersionNumber\"";
    SQL minorVerResults(minorVerQuery);
    if (!minorVerResults.rows().empty()) {
      r["minor"] = minorVerResults.rows()[0].at("data");
    } else {
      separateVersionkeys = false;
    }

    // On windows 10 and above the version numbers are stored in separate major
    // and minor values. In earlier versions these are stored in a single value.
    if (!separateVersionkeys) {
      std::string combinedVersionQuery =
          "SELECT data FROM registry WHERE path = \"" + osCurrentVersionKey +
          "\\CurrentVersion\"";
      SQL combinedVersionResults(combinedVersionQuery);
      if (!combinedVersionResults.rows().empty()) {
        std::string combinedVersion =
            combinedVersionResults.rows()[0].at("data");
        r["major"] = combinedVersion.substr(0, combinedVersion.find("."));
        r["minor"] = combinedVersion.substr(combinedVersion.find(".") + 1);
      }
    }

    std::string buildNumberQuery = "SELECT data FROM registry WHERE path = \"" +
                                   osCurrentVersionKey +
                                   "\\CurrentBuildNumber\"";
    SQL buildNumberResults(buildNumberQuery);
    if (!buildNumberResults.rows().empty()) {
      r["build"] = buildNumberResults.rows()[0].at("data");
    }

    SYSTEM_INFO systemInfo = {};
    GetNativeSystemInfo(&systemInfo);
    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
      r["arch"] = "64-bit";
    } else if (systemInfo.wProcessorArchitecture ==
               PROCESSOR_ARCHITECTURE_ARM64) {
      r["arch"] = "ARM 64-bit";
    } else if (systemInfo.wProcessorArchitecture ==
               PROCESSOR_ARCHITECTURE_INTEL) {
      r["arch"] = "32-bit";
    }
  } else {
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
  }

  r["platform"] = "windows";
  r["platform_like"] = "windows";
  r["version"] = r["major"] + "." + r["minor"] + "." + r["build"];

  return {r};
}
} // namespace tables
} // namespace osquery
