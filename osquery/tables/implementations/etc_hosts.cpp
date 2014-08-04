// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/implementations/etc_hosts.h"

#include <vector>
#include <string>

#include <boost/algorithm/string/predicate.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/filesystem.h"

using namespace osquery::core;
using namespace osquery::db;
using namespace osquery::fs;

namespace osquery { namespace tables {

QueryData genEtcHosts() {
  std::string content;
  auto s = readFile("/etc/hosts", content);
  if (s.ok()) {
    return parseEtcHostsContent(content);
  } else {
    LOG(ERROR) << "Error reading /etc/hosts: " << s.toString();
    return {};
  }
}

QueryData parseEtcHostsContent(const std::string& content) {
  QueryData results;

  for (const auto& i : splitString(content, '\n')) {
    auto line = splitString(i, ' ');
    if (line.size() == 0 || boost::starts_with(line[0], "#")) {
      continue;
    }
    Row r;
    r["address"] = line[0];
    line.erase(line.begin());
    r["hostnames"] = joinString(line, ' ');
    results.push_back(r);
  }

  return results;
}

}}
