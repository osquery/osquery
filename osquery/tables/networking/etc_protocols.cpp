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
fs::path kEtcProtocols = "/etc/protocols";
#else
fs::path kEtcProtocols = (getSystemRoot() / "system32\\drivers\\etc\\protocol");
#endif

QueryData parseEtcProtocolsContent(const std::string& content) {
  QueryData results;

  for (const auto& line : osquery::split(content, "\n")) {
    // Empty line or comment.
    if (line.size() == 0 || boost::starts_with(line, "#")) {
      continue;
    }

    // [0]: name protocol_number alias
    // [1]: [comment part1]
    // [2]: [comment part2]
    // [n]: [comment partn]
    auto protocol_comment = osquery::split(line, "#");

    // [0]: name
    // [1]: protocol_number
    // [2]: alias
    auto protocol_fields = osquery::split(protocol_comment[0]);
    if (protocol_fields.size() < 2) {
      continue;
    }

    Row r;
    r["name"] = SQL_TEXT(protocol_fields[0]);
    r["number"] = INTEGER(protocol_fields[1]);
    if (protocol_fields.size() > 2) {
      r["alias"] = SQL_TEXT(protocol_fields[2]);
    }

    // If there is a comment for the service.
    if (protocol_comment.size() > 1) {
      // Removes everything except the comment (parts of the comment).
      protocol_comment.erase(protocol_comment.begin(),
                             protocol_comment.begin() + 1);
      r["comment"] = SQL_TEXT(boost::algorithm::join(protocol_comment, " # "));
    }
    results.push_back(r);
  }
  return results;
}

QueryData genEtcProtocols(QueryContext& context) {
  std::string content;
  auto s = readFile(kEtcProtocols, content);
  if (s.ok()) {
    return parseEtcProtocolsContent(content);
  } else {
    TLOG << "Error reading " << kEtcProtocols << ": " << s.toString();
    return {};
  }
}
}
}
