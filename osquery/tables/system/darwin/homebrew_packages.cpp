/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kHomebrewRoot = "/usr/local/Cellar/";

std::vector<std::string> getHomebrewAppInfoPlistPaths() {
  std::vector<std::string> results;
  auto status = osquery::listDirectoriesInDirectory(kHomebrewRoot, results);
  if (!status.ok()) {
    TLOG << "Error listing " << kHomebrewRoot << ": " << status.toString();
  }

  return results;
}

std::string getHomebrewNameFromInfoPlistPath(const std::string& path) {
  auto bits = osquery::split(path, "/");
  return bits[bits.size() - 1];
}

std::vector<std::string> getHomebrewVersionsFromInfoPlistPath(
    const std::string& path) {
  std::vector<std::string> results;
  std::vector<std::string> app_versions;
  auto status = osquery::listDirectoriesInDirectory(path, app_versions);
  if (status.ok()) {
    for (const auto& version : app_versions) {
      results.push_back(fs::path(version).filename().string());
    }
  } else {
    TLOG << "Error listing " << path << ": " << status.toString();
  }

  return results;
}

QueryData genHomebrewPackages(QueryContext& context) {
  QueryData results;

  for (const auto& path : getHomebrewAppInfoPlistPaths()) {
    auto versions = getHomebrewVersionsFromInfoPlistPath(path);
    auto name = getHomebrewNameFromInfoPlistPath(path);
    for (const auto& version : versions) {
      // Support a many to one version to package name.
      Row r;
      r["name"] = name;
      r["path"] = path;
      r["version"] = version;

      results.push_back(r);
    }
  }
  return results;
}
}
}
