/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <unistd.h>

#include <map>
#include <string>

#include <boost/algorithm/string/find.hpp>
#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>

#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

namespace xp = boost::xpressive;

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  static const std::string kSysctlName = "kern.osrelease";

  auto result =
      SQL::selectAllFrom("system_controls", "name", EQUALS, kSysctlName);

  Row r;

  r["name"] = "FreeBSD";

  // TODO: Patchlevel isn't matched for some reason
  auto rx = xp::sregex::compile(
      "(?P<major>[0-9]+)\\.(?P<minor>[0-9]+)-(?P<build>\\w+)-?(?P<patch>\\w+)"
      "?");

  xp::smatch matches;
  for (auto& line : osquery::split(result[0]["current_value"], "\n")) {
    if (xp::regex_search(line, matches, rx)) {
      r["major"] = INTEGER(matches["major"]);
      r["minor"] = INTEGER(matches["minor"]);
      r["build"] = matches["build"];
      r["patch"] = matches["patch"];
      break;
    }
  }

  return {r};
}

QueryData genSystemInfo(QueryContext& context) {
  return QueryData();
}

QueryData genPlatformInfo(QueryContext& context) {
  return QueryData();
}
}
}
