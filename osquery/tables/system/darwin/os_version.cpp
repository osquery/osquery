/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_os_version_defs.hpp>

namespace osquery {
namespace tables {

const std::string kVersionPath{
    "/System/Library/CoreServices/SystemVersion.plist"};

QueryData genOSVersion(QueryContext& context) {
  Row r;
  r["platform"] = "darwin";
  r["platform_like"] = "darwin";

  // The version path plist is parsed by the OS X tool: sw_vers.
  auto sw_vers = SQL::selectAllFrom("plist", "path", EQUALS, kVersionPath);
  if (sw_vers.empty()) {
    return {r};
  }

  for (const auto& row : sw_vers) {
    // Iterate over each plist key searching for the version string.
    if (row.at("key") == "ProductBuildVersion") {
      r["build"] = row.at("value");
    } else if (row.at("key") == "ProductVersion") {
      r["version"] = row.at("value");
    } else if (row.at("key") == "ProductName") {
      r["name"] = row.at("value");
    }
  }

  r["patch"] = "0";
  auto version = osquery::split(r["version"], ".");
  switch (version.size()) {
  case 3:
    r["patch"] = INTEGER(version[2]);
  case 2:
    r["minor"] = INTEGER(version[1]);
  case 1:
    r["major"] = INTEGER(version[0]);
    break;
  }
  return {r};
}
}
}
