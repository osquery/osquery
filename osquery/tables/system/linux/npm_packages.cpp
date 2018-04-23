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

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::map<std::string, std::string> PackageTopLevelKeys{
    {"name", "name"},
    {"version", "version"},
    {"description", "description"},
    {"author.name", "author"},
    {"license", "license"}};

QueryData genNPMPackages(QueryContext& context) {
  QueryData results;

  std::vector<std::string> paths;
  resolveFilePattern("/usr/lib/node_modules/%/package.json", paths);

  for (const auto& path : paths) {
    pt::ptree tree;
    if (!osquery::parseJSON(path, tree).ok()) {
      LOG(WARNING) << "Could not parse JSON from: " << path;
    }

    Row r;
    for (const auto& it : PackageTopLevelKeys) {
      std::string val = tree.get(it.first, "");
      r[it.second] = val;
    }
    r["path"] = path;

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
