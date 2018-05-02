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

namespace osquery {
namespace tables {

const std::vector<std::string> kPackageKeys{
    "name", "version", "description", "license"};

const std::string kLinuxNodeModulesPath{"/usr/lib/"};

void genPackageResults(const std::string& directory, QueryData& results) {
  std::vector<std::string> packages;
  resolveFilePattern(directory + "/node_modules/%/package.json", packages);

  for (const auto& package_path : packages) {
    std::string json;
    if (!readFile(package_path, json).ok()) {
      LOG(WARNING) << "Could not read package JSON: " << package_path;
      continue;
    }

    auto doc = JSON::newObject();
    if (!doc.fromString(json) || !doc.doc().IsObject()) {
      LOG(WARNING) << "Could not parse JSON from: " << package_path;
      continue;
    }

    Row r;
    for (const auto& key : kPackageKeys) {
      if (doc.doc().HasMember(key)) {
        const auto& value = doc.doc()[key];
        r[key] = (value.IsString()) ? value.GetString() : "";
      }
    }

    r["path"] = package_path;
    r["directory"] = directory;

    // Manually get nested key (Author name)
    if (doc.doc().HasMember("author")) {
      const auto& author = doc.doc()["author"]["name"];
      r["author"] = (author.IsString()) ? author.GetString() : "";
    }

    results.push_back(r);
  }
}

QueryData genNPMPackages(QueryContext& context) {
  QueryData results;

  std::set<std::string> search_directories = {kLinuxNodeModulesPath};
  if (context.constraints.count("directory") > 0 &&
      context.constraints.at("directory").exists(EQUALS)) {
    search_directories = context.constraints["directory"].getAll(EQUALS);
  }

  for (const auto& directory : search_directories) {
    genPackageResults(directory, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
