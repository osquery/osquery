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

#define WMI_QUERY "SELECT CAPTION,VERSION FROM Win32_OperatingSystem"

QueryData genOSVersion(QueryContext& context) {
  WmiRequest wmiRequest(WMI_QUERY);
  std::vector<WmiResultItem>& wmiResults = wmiRequest.results();

  if (wmiResults.size() == 0) {
    return {};
  }

  Row r;
  std::string version_string;

  wmiResults[0].GetString("Caption", r["name"]);
  wmiResults[0].GetString("Version", version_string);
  auto version = osquery::split(version_string, ".");

  switch (version.size()) {
  case 3:
    r["build"] = INTEGER(version[2]);
  case 2:
    r["minor"] = INTEGER(version[1]);
    r["major"] = INTEGER(version[0]);
    break;
  }
  return {r};
}
}
}
