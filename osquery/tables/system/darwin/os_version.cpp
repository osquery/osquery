/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

#define OSX_VERSION_PATH "/System/Library/CoreServices/SystemVersion.plist"

QueryData genOSVersion(QueryContext& context) {
  // The version path plist is parsed by the OS X tool: sw_vers.
  auto sw_vers =
      SQL::selectAllFrom("preferences", "path", EQUALS, OSX_VERSION_PATH);
  if (sw_vers.size() == 0) {
    return {};
  }

  std::string version_string;
  Row r;
  for (const auto& row : sw_vers) {
    // Iterate over each plist key searching for the version string.
    if (row.at("key") == "ProductBuildVersion") {
      r["build"] = row.at("value");
    } else if (row.at("key") == "ProductVersion") {
      version_string = row.at("value");
    } else if (row.at("key") == "ProductName") {
      r["name"] = row.at("value");
    }
  }

  r["patch"] = "0";
  auto version = osquery::split(version_string, ".");
  switch (version.size()) {
  case 3:
    r["patch"] = INTEGER(version[2]);
  case 2:
    r["minor"] = INTEGER(version[1]);
    r["major"] = INTEGER(version[0]);
    break;
  }
  return {r};
}
}
}
