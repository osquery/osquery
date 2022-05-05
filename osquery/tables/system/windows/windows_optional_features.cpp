/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

std::string getDismPackageFeatureStateName(uint32_t state);

/**
 * return collection of Windows Features installation states.
 * On Window 10 Pro, returns about 140 rows.
 */
QueryData genWinOptionalFeatures(QueryContext& context) {
  QueryData results;

  const auto wmiReq = WmiRequest::CreateWmiRequest(
      "SELECT Caption,Name,InstallState FROM Win32_OptionalFeature");
  if (!wmiReq) {
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = wmiReq->results();
  if (wmiResults.empty()) {
    return results;
  }

  for (const auto& wmiObj : wmiResults) {
    Row r;
    uint32_t state;

    wmiObj.GetString("Name", r["name"]);
    wmiObj.GetString("Caption", r["caption"]);

    // wbemtest.exe shows Column as UINT32, but comes in as I4.
    // For whatever reason, I4 is accessed using GetLong().

    if (wmiObj.GetUnsignedInt32("InstallState", state).ok() == false) {
      long state_long;
      if (wmiObj.GetLong("InstallState", state_long).ok()) {
        state = static_cast<uint32_t>(state_long);
      }
    }
    r["state"] = INTEGER(state);

    r["statename"] = getDismPackageFeatureStateName(state);
    results.push_back(r);
  }
  return results;
}

/**
 *
 * https://docs.microsoft.com/en-us/windows/desktop/CIMWin32Prov/win32-optionalfeature
 * Enabled (1)
 * Disabled (2)
 * Absent (3)
 * Unknown (4)
 */
std::string getDismPackageFeatureStateName(uint32_t state) {
  const std::vector<std::string> stateNames = {
      "Unknown", "Enabled", "Disabled", "Absent"};

  if (state >= stateNames.size()) {
    return "Unknown";
  }

  return stateNames[state];
}

} // namespace tables
} // namespace osquery
