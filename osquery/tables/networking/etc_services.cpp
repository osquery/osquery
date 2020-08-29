/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;

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
    r["name"] = SQL_TEXT(service_info[0]);
    r["port"] = INTEGER(service_port_protocol[0]);
    r["protocol"] = SQL_TEXT(service_port_protocol[1]);

    // Removes the name and the port/protcol elements.
    service_info.erase(service_info.begin(), service_info.begin() + 2);
    r["aliases"] = SQL_TEXT(boost::algorithm::join(service_info, " "));

    // If there is a comment for the service.
    if (service_info_comment.size() > 1) {
      // Removes everything except the comment (parts of the comment).
      service_info_comment.erase(service_info_comment.begin(),
                                 service_info_comment.begin() + 1);
      r["comment"] =
          SQL_TEXT(boost::algorithm::join(service_info_comment, " # "));
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
} // namespace tables
} // namespace osquery
