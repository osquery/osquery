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
#include <osquery/sql.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::map<std::string, std::string> kAppsInfoPlistTopLevelStringKeys = {
    {"CFBundleExecutable", "bundle_executable"},
    {"CFBundleIdentifier", "bundle_identifier"},
    {"CFBundleName", "bundle_name"},
    {"CFBundleShortVersionString", "bundle_short_version"},
    {"CFBundleVersion", "bundle_version"},
    {"CFBundlePackageType", "bundle_package_type"},
    {"LSEnvironment", "environment"},
    {"LSUIElement", "element"},
    {"CFBundleDevelopmentRegion", "development_region"},
    {"CFBundleDisplayName", "display_name"},
    {"CFBundleGetInfoString", "info_string"},
    {"DTCompiler", "compiler"},
    {"LSMinimumSystemVersion", "minimum_system_version"},
    {"LSApplicationCategoryType", "category"},
    {"NSAppleScriptEnabled", "applescript_enabled"},
    {"NSHumanReadableCopyright", "copyright"},
};

const std::vector<std::string> kHomeDirSearchPaths = {
    "Applications", "Desktop", "Downloads",
};

void genApplicationsFromPath(const fs::path& path,
                             std::vector<std::string>& apps) {
  std::vector<std::string> new_apps;
  if (!osquery::listDirectoriesInDirectory(path.string(), new_apps).ok()) {
    return;
  }

  for (const auto& app : new_apps) {
    if (fs::exists(app + "/Contents/Info.plist")) {
      apps.push_back(app + "/Contents/Info.plist");
    }
  }
}

void genApplication(const pt::ptree& tree,
                    const fs::path& path,
                    QueryData& results) {
  Row r;
  r["name"] = path.parent_path().parent_path().filename().string();
  r["path"] = path.parent_path().parent_path().string();

  // Loop through each column and its mapped Info.plist key name.
  for (const auto& item : kAppsInfoPlistTopLevelStringKeys) {
    try {
      r[item.second] = tree.get<std::string>(item.first);
      // Change boolean values into integer 1, 0.
      if (r[item.second] == "true" || r[item.second] == "YES" ||
          r[item.second] == "Yes") {
        r[item.second] = INTEGER(1);
      } else if (r[item.second] == "false" || r[item.second] == "NO" ||
                 r[item.second] == "No") {
        r[item.second] = INTEGER(0);
      }
    } catch (const pt::ptree_error& e) {
      // Expect that most of the selected keys are missing.
      r[item.second] = "";
    }
  }
  results.push_back(r);
}

QueryData genApps(QueryContext& context) {
  QueryData results;

  // Walk through several groups of common search paths that may contain apps.
  std::vector<std::string> apps;
  genApplicationsFromPath("/Applications", apps);

  // List all users on the system, and walk common search paths with homes.
  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    for (const auto& path : kHomeDirSearchPaths) {
      genApplicationsFromPath(home / path, apps);
    }
  }

  // The osquery::parsePlist method will reset/clear a property tree.
  // Keeping the data structure in a larger scope preserves allocations
  // between similar-sized trees.
  pt::ptree tree;

  // For each found application (path with an Info.plist) parse the plist.
  for (const auto& path : apps) {
    if (!context.constraints["path"].matches(path)) {
      // Optimize by not searching when a path is a constraint.
      continue;
    }

    if (!osquery::parsePlist(path, tree).ok()) {
      TLOG << "Error parsing application plist: " << path;
      continue;
    }

    // Using the parsed plist, pull out each interesting key.
    genApplication(tree, path, results);
  }

  return results;
}
}
}
