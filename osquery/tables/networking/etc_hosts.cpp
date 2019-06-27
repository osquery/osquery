/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

#ifndef WIN32
fs::path kEtcHosts = "/etc/hosts";
#else
fs::path kEtcHosts = (getSystemRoot() / "system32\\drivers\\etc\\hosts");
fs::path kEtcHostsIcs = (getSystemRoot() / "system32\\drivers\\etc\\hosts.ics");
#endif
QueryData parseEtcHostsContent(const std::string& content) {
  QueryData results;

  for (const auto& _line : osquery::split(content, "\n")) {
    auto line = split(_line);
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
  QueryData qres = {};

  if (readFile(kEtcHosts, content).ok()) {
    qres = parseEtcHostsContent(content);
  }

#ifdef WIN32
  content.clear();
  QueryData qres_ics = {};
  if (readFile(kEtcHostsIcs, content).ok()) {
    qres_ics = parseEtcHostsContent(content);
    qres.insert(qres.end(), qres_ics.begin(), qres_ics.end());
  }
#endif

  return qres;
}
}
}
