/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/property_tree/ini_parser.hpp>
#include <iostream>
#include <fstream>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

const std::string kYumConf { "/etc/yum.conf" };
const std::string kYumReposDir { "/etc/yum.repos.d" };

void parseYumConf(std::istream& source, QueryData& results, std::string& repos_dir) {
  boost::property_tree::ptree tree;
  boost::property_tree::ini_parser::read_ini(source, tree);
  repos_dir = tree.get("main.reposdir", kYumReposDir);

  for (auto it1: tree) {
    // Section
    if (it1.first == "main") {
      continue;
    }

    Row r;
    for (auto it2: it1.second) {
      // Option
      if ("baseurl" == it2.first || "enabled" == it2.first
          || "gpgcheck" == it2.first || "name" == it2.first
          || "gpgkey" == it2.first) {
        r[it2.first] = it2.second.data();
      }
    }
    results.push_back(r);
  }
}

void parseYumConf(const std::string& source, QueryData& results, std::string& repos_dir) {
  std::ifstream stream(source.c_str());
  if (!stream) {
    VLOG(1) << "File " << source << " cannot be read";
    repos_dir = kYumReposDir;
    return;
  }

  try {
    parseYumConf(stream, results, repos_dir);
  } catch (boost::property_tree::ini_parser::ini_parser_error& e) {
    VLOG(1) << "File " << source
      << " either cannot be read or cannot be parsed as ini";
    repos_dir = kYumReposDir;
  }
}

QueryData genYumSrcs(QueryContext& context) {
  QueryData results;

  // We are going to read a few files.
  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  // Expect the YUM home to be /etc/yum.conf
  std::string repos_dir;
  parseYumConf(kYumConf, results, repos_dir);

  std::vector<std::string> sources;
  if (!resolveFilePattern(repos_dir + "/%.list", sources, GLOB_FILES)) {
    VLOG(1) << "Cannot resolve yum conf files under " << repos_dir << "/*.list";
    return results;
  }

  for (const auto& source : sources) {
    parseYumConf(source, results, repos_dir);
  }

  return results;
}
} // namespace tables
} // namespace osquery
