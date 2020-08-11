/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unistd.h>

#include <map>
#include <regex>
#include <string>

#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/split.h>

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

  auto rx = std::regex("([0-9]+)\\.([0-9]+)-(\\w+)-?p?([0-9]+)?");

  std::smatch matches;
  for (auto& line : osquery::split(result[0]["current_value"], "\n")) {
    if (std::regex_search(line, matches, rx)) {
      r["major"] = matches[1];
      r["minor"] = matches[2];
      r["build"] = matches[3];
      r["patch"] = matches[4];
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
