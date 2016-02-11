/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

QueryData parseEtcProtocolsContent(const std::string& content) {
  QueryData results;

  for (const auto& line : split(content, "\n")) {
    // Empty line or comment.
    if (line.size() == 0 || boost::starts_with(line, "#")) {
      continue;
    }

    // [0]: name protocol_number alias
    // [1]: [comment part1]
    // [2]: [comment part2]
    // [n]: [comment partn]
    auto protocol_comment = split(line, "#");

    // [0]: name
    // [1]: protocol_number
    // [2]: alias
    auto protocol_fields = split(protocol_comment[0]);
    if (protocol_fields.size() < 2) {
      continue;
    }

    Row r;
    r["name"] = TEXT(protocol_fields[0]);
    r["number"] = INTEGER(protocol_fields[1]);
    if (protocol_fields.size() > 2) {
      r["alias"] = TEXT(protocol_fields[2]);
    }

    // If there is a comment for the service.
    if (protocol_comment.size() > 1) {
      // Removes everything except the comment (parts of the comment).
      protocol_comment.erase(protocol_comment.begin(),
                             protocol_comment.begin() + 1);
      r["comment"] = TEXT(boost::algorithm::join(protocol_comment, " # "));
    }
    results.push_back(r);
  }
  return results;
}

QueryData genEtcProtocols(QueryContext& context) {
  std::string content;
  auto s = osquery::forensicReadFile("/etc/protocols", content);
  if (s.ok()) {
    return parseEtcProtocolsContent(content);
  } else {
    TLOG << "Error reading /etc/protocols: " << s.toString();
    return {};
  }
}
}
}
