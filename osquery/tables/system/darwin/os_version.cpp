/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cerrno>
#include <sys/utsname.h>

#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

const std::string kVersionPath{
    "/System/Library/CoreServices/SystemVersion.plist"};

QueryData genOSVersion(QueryContext& context) {
  Row r;
  r["platform"] = "darwin";
  r["platform_like"] = "darwin";

  struct utsname uname_buf {};

  if (uname(&uname_buf) == 0) {
    r["arch"] = TEXT(uname_buf.machine);
  } else {
    LOG(INFO) << "Failed to determine the OS architecture, error " << errno;
  }

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
