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
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

QueryData parseEtcHostsContent(const std::string& content) {
  QueryData results;

  for (const auto& i : osquery::split(content, "\n")) {
    auto line = split(i);
    if (line.size() == 0 || boost::starts_with(line[0], "#")) {
      continue;
    }
    Row r;
    r["address"] = line[0];
    if (line.size() > 1) {
      std::vector<std::string> hostnames;
      for (size_t i = 1; i < line.size(); ++i) {
        if (boost::starts_with(line[i], "#")) {
          break;
        }
        hostnames.push_back(line[i]);
      }
      r["hostnames"] = boost::algorithm::join(hostnames, " ");
    }
    results.push_back(r);
  }

  return results;
}

QueryData genEtcHosts(QueryContext& context) {
  std::string content;
  auto s = readFile("/etc/hosts", content);
  if (s.ok()) {
    return parseEtcHostsContent(content);
  } else {
    return {};
  }
}
}
}
