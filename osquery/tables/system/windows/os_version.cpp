/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  const std::string kWmiQuery =
      "SELECT CAPTION,VERSION FROM Win32_OperatingSystem";

  WmiRequest wmiRequest(kWmiQuery);
  std::vector<WmiResultItem>& wmiResults = wmiRequest.results();

  if (wmiResults.empty()) {
    return {};
  }

  Row r;
  std::string version_string;

  wmiResults[0].GetString("Caption", r["name"]);
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
  return {r};
}
}
}
