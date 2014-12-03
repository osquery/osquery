// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <glog/logging.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

QueryData parseEtcHostsContent(const std::string& content) {
  QueryData results;

  for (const auto& i : split(content, "\n")) {
    auto line = split(i);
    if (line.size() == 0 || boost::starts_with(line[0], "#")) {
      continue;
    }
    Row r;
    r["address"] = line[0];
    if (line.size() > 1) {
      std::vector<std::string> hostnames;
      for (int i = 1; i < line.size(); ++i) {
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
  auto s = osquery::readFile("/etc/hosts", content);
  if (s.ok()) {
    return parseEtcHostsContent(content);
  } else {
    LOG(ERROR) << "Error reading /etc/hosts: " << s.toString();
    return {};
  }
}
}
}
