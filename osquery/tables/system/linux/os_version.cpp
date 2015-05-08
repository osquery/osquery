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

#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>

#include <osquery/filesystem.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace xp = boost::xpressive;

namespace osquery {
namespace tables {

#if defined(CENTOS) || defined(RHEL)
const std::string kLinuxOSRelease = "/etc/redhat-release";
const std::string kLinuxOSRegex =
    "(?P<name>\\w+) .* "
    "(?P<major>[0-9]+).(?P<minor>[0-9]+)[\\.]{0,1}(?P<patch>[0-9]+)";
#else
const std::string kLinuxOSRelease = "/etc/os-release";
const std::string kLinuxOSRegex =
    "VERSION=\"(?P<major>[0-9]+)\\.(?P<minor>[0-9]+)[\\.]{0,1}(?P<patch>[0-9]+)"
    "?.*, (?P<name>[\\w ]*)\"$";
#endif

QueryData genOSVersion(QueryContext& context) {
  std::string content;
  if (!readFile(kLinuxOSRelease, content).ok()) {
    return {};
  }

  Row r;
  auto rx = xp::sregex::compile(kLinuxOSRegex);
  xp::smatch matches;
  for (const auto& line : osquery::split(content, "\n")) {
    if (xp::regex_search(line, matches, rx)) {
      r["major"] = INTEGER(matches["major"]);
      r["minor"] = INTEGER(matches["minor"]);
      r["patch"] =
          (matches["patch"].length() > 0) ? INTEGER(matches["patch"]) : "0";
      r["name"] = matches["name"];
      break;
    }
  }

  // No build name.
  r["build"] = "";
  return {r};
}
}
}
