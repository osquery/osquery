/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <unistd.h>

#include <map>
#include <string>

#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/trim.hpp>
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
  r["platform"] = "freebsd";
  r["version"] = result[0]["current_value"];

  auto rx = xp::sregex::compile(
      "(?P<major>[0-9]+)\\.(?P<minor>[0-9]+)-(?P<build>\\w+)-?p?(?P<patch>[0-9]+)"
      "?");

  xp::smatch matches;
  for (auto& line : osquery::split(result[0]["current_value"], "\n")) {
    if (xp::regex_search(line, matches, rx)) {
      r["major"] = matches["major"];
      r["minor"] = matches["minor"];
      r["build"] = matches["build"];
      r["patch"] = matches["patch"];
      break;
    }
  }

  return {r};
}

QueryData genSystemInfo(QueryContext& context) {
  Row r;
  r["hostname"] = osquery::getHostname();
  r["computer_name"] = r["hostname"];

  std::string uuid;
  r["uuid"] = (osquery::getHostUUID(uuid)) ? uuid : "";

  auto qd = SQL::selectAllFrom("cpuid");
  for (const auto& row : qd) {
    if (row.at("feature") == "product_name") {
      r["cpu_brand"] = row.at("value");
      boost::trim(r["cpu_brand"]);
    }
  }

  static long cores = sysconf(_SC_NPROCESSORS_CONF);
  if (cores > 0) {
    r["cpu_logical_cores"] = INTEGER(cores);
    r["cpu_physical_cores"] = INTEGER(cores);
  } else {
    r["cpu_logical_cores"] = "-1";
    r["cpu_physical_cores"] = "-1";
  }

  static long pages = sysconf(_SC_PHYS_PAGES);
  static long pagesize = sysconf(_SC_PAGESIZE);

  if (pages > 0 && pagesize > 0) {
    r["physical_memory"] = BIGINT((long long)pages * (long long)pagesize);
  } else {
    r["physical_memory"] = "-1";
  }

  r["cpu_type"] = "0";
  r["cpu_subtype"] = "0";

  return {r};
}

QueryData genPlatformInfo(QueryContext& context) {
  return QueryData();
}
}
}
