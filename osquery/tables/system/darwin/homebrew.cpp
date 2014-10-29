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

const char* HOMEBREW_ROOT_DIR = "/usr/local/Cellar/";

std::vector<std::string> getHomebrewAppInfoPlistPaths() {
  std::vector<std::string> results;

  std::vector<std::string> slash_applications;
  auto slash_apps_s =
      osquery::listFilesInDirectory(HOMEBREW_ROOT_DIR, slash_applications);
  if (slash_apps_s.ok()) {
    for (const auto& app_path : slash_applications) {
      results.push_back(app_path);
    }
  } else {
    LOG(ERROR) << "Error listing " << HOMEBREW_ROOT_DIR << ": "
               << slash_apps_s.toString();
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

  std::vector<std::string> slash_versions;
  auto slash_versions_s = osquery::listFilesInDirectory(path, slash_versions);
  if (slash_versions_s.ok()) {
    for (const auto& version_path : slash_versions) {
      auto bits = osquery::split(version_path, "/");
      results.push_back(bits[bits.size() - 1]);
    }
  } else {
    LOG(ERROR) << "Error listing " << path << ": "
               << slash_versions_s.toString();
  }

  return results;
}

QueryData genHomebrew() {
  QueryData results;

  for (const auto& path : getHomebrewAppInfoPlistPaths()) {

    std::vector<std::string> versions =
        getHomebrewVersionsFromInfoPlistPath(path);
    std::string name = getHomebrewNameFromInfoPlistPath(path);
    for (const auto& version : versions) {
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
