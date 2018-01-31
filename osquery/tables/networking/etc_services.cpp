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
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/filesystem/fileops.h"

namespace fs = boost::filesystem;

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_etc_services_defs.hpp>

namespace osquery {
namespace tables {

#ifndef WIN32
fs::path kEtcServices = "/etc/services";
#else
fs::path kEtcServices = (getSystemRoot() / "system32\\drivers\\etc\\services");
#endif

QueryData parseEtcServicesContent(const std::string& content) {
  QueryData results;

  for (const auto& line : osquery::split(content, "\n")) {
    // Empty line or comment.
    if (line.size() == 0 || boost::starts_with(line, "#")) {
      continue;
    }

    // [0]: name port/protocol [aliases]
    // [1]: [comment part1]
    // [2]: [comment part2]
    // [n]: [comment partn]
    auto service_info_comment = osquery::split(line, "#");

    // [0]: name
    // [1]: port/protocol
    // [2]: [aliases0]
    // [3]: [aliases1]
    // [n]: [aliasesn]
    auto service_info = osquery::split(service_info_comment[0]);
    if (service_info.size() < 2) {
      continue;
    }

    // [0]: port [1]: protocol
    auto service_port_protocol = osquery::split(service_info[1], "/");
    if (service_port_protocol.size() != 2) {
      continue;
    }

    Row r;
    r["name"] = TEXT(service_info[0]);
    r["port"] = INTEGER(service_port_protocol[0]);
    r["protocol"] = TEXT(service_port_protocol[1]);

    // Removes the name and the port/protcol elements.
    service_info.erase(service_info.begin(), service_info.begin() + 2);
    r["aliases"] = TEXT(boost::algorithm::join(service_info, " "));

    // If there is a comment for the service.
    if (service_info_comment.size() > 1) {
      // Removes everything except the comment (parts of the comment).
      service_info_comment.erase(service_info_comment.begin(),
                                 service_info_comment.begin() + 1);
      r["comment"] = TEXT(boost::algorithm::join(service_info_comment, " # "));
    }
    results.push_back(r);
  }
  return results;
}

QueryData genEtcServices(QueryContext& context) {
  std::string content;
  auto s = readFile(kEtcServices, content);
  if (s.ok()) {
    return parseEtcServicesContent(content);
  } else {
    TLOG << "Error reading " << kEtcServices << ": " << s.toString();
    return {};
  }
}
}
}
