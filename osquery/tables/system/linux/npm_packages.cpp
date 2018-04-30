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
#include "osquery/core/json.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::map<std::string, std::string> kPackageTopLevelKeys{
    {"name", "name"},
    {"version", "version"},
    {"description", "description"},
    {"license", "license"}};

const std::string kLinuxNodeModulesPath = "/usr/lib/";

QueryData genNPMPackages(QueryContext& context) {
  QueryData results;

  std::string searchDirectory = "";
  if (context.constraints.count("directory") > 0 &&
      context.constraints.at("directory").exists(EQUALS)) {
    auto wherePath = (*context.constraints["directory"].getAll(EQUALS).begin());
    searchDirectory = wherePath;
  } else {
    searchDirectory = kLinuxNodeModulesPath;
  }

  std::vector<std::string> paths;
  resolveFilePattern(searchDirectory + "/node_modules/%/package.json", paths);

  for (const auto& path : paths) {
    std::string json;
    if (!readFile(path, json).ok()) {
      LOG(WARNING) << "Could not read package JSON: " << path;
      continue;
    }

    auto doc = JSON::newObject();
    if (!doc.fromString(json) || !doc.doc().IsObject()) {
      LOG(WARNING) << "Could not parse JSON from: " << path;
      continue;
    }

    Row r;
    for (const auto& it : kPackageTopLevelKeys) {
      std::string key = it.first;
      if (doc.doc().HasMember(key)) {
        const auto& value = doc.doc()[key];
        r[it.second] = (value.IsString()) ? value.GetString() : "";
      }
    }

    r["path"] = path;
    r["directory"] = searchDirectory;

    // Manually get nested key (Author name)
    if (doc.doc().HasMember("author")) {
      const auto& author = doc.doc()["author"]["name"];
      r["author"] = (author.IsString()) ? author.GetString() : "";
    }

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
