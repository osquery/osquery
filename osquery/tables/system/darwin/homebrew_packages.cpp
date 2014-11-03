// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kHomebrewRoot = "/usr/local/Cellar/";

std::vector<std::string> getHomebrewAppInfoPlistPaths() {
  std::vector<std::string> results;

  std::vector<std::string> homebrew_apps;
  auto status = osquery::listFilesInDirectory(kHomebrewRoot, homebrew_apps);
  if (status.ok()) {
    for (const auto& app_path : homebrew_apps) {
      results.push_back(app_path);
    }
  } else {
    LOG(ERROR) << "Error listing " << kHomebrewRoot << ": "
               << status.toString();
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
  auto status = osquery::listFilesInDirectory(path, app_versions);
  if (status.ok()) {
    for (const auto& version_path : app_versions) {
      auto bits = osquery::split(version_path, "/");
      results.push_back(bits[bits.size() - 1]);
    }
  } else {
    LOG(ERROR) << "Error listing " << path << ": " << status.toString();
  }

  return results;
}

QueryData genHomebrewPackages() {
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
