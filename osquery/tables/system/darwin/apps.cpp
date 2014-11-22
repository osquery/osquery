// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

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
    "/Applications", "/Desktops", "/Downloads",
};

std::vector<std::string> getAppInfoPlistPaths() {
  std::vector<std::string> results;

  std::vector<std::string> slash_applications;
  auto slash_apps_s =
      osquery::listFilesInDirectory("/Applications", slash_applications);
  if (slash_apps_s.ok()) {
    for (const auto& app_path : slash_applications) {
      std::string path = app_path + "/Contents/Info.plist";
      if (boost::filesystem::exists(path)) {
        results.push_back(path);
      }
    }
  } else {
    LOG(ERROR) << "Error listing /Applications: " << slash_apps_s.toString();
  }

  std::vector<std::string> home_dirs;
  auto home_dirs_s = osquery::listFilesInDirectory("/Users", home_dirs);
  if (home_dirs_s.ok()) {
    for (const auto& home_dir : home_dirs) {
      for (const auto& dir_to_check : kHomeDirSearchPaths) {
        std::string apps_path = home_dir + dir_to_check;
        if (boost::filesystem::is_directory(apps_path)) {
          std::vector<std::string> user_apps;
          auto user_apps_s =
              osquery::listFilesInDirectory(apps_path, user_apps);
          if (!user_apps_s.ok()) {
            VLOG(1) << "Error listing " << apps_path << ": "
                    << user_apps_s.toString();
            continue;
          }
          for (const auto& user_app : user_apps) {
            std::string path = user_app + "/Contents/Info.plist";
            if (boost::filesystem::exists(path)) {
              results.push_back(path);
            }
          }
        }
      }
    }
  } else {
    LOG(ERROR) << "Error listing /Users: " << home_dirs_s.toString();
  }

  return results;
}

std::string getNameFromInfoPlistPath(const std::string& path) {
  auto bits = osquery::split(path, "/");
  if (bits.size() >= 4) {
    return bits[bits.size() - 3];
  } else {
    return "";
  }
}

std::string getPathFromInfoPlistPath(const std::string& path) {
  auto bits = osquery::split(path, "/");
  if (bits.size() >= 4) {
    bits.pop_back();
    bits.pop_back();
    return "/" + boost::algorithm::join(bits, "/");
  } else {
    return "";
  }
}

Row parseInfoPlist(const std::string& path, const pt::ptree& tree) {
  Row r;
  r["name"] = getNameFromInfoPlistPath(path);
  r["path"] = getPathFromInfoPlistPath(path);
  for (const auto& it : kAppsInfoPlistTopLevelStringKeys) {
    try {
      r[it.second] = tree.get<std::string>(it.first);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error retrieving " << it.first << " from " << path << ": "
              << e.what();
      r[it.second] = "";
    }
  }
  return r;
}

QueryData genApps() {
  QueryData results;

  for (const auto& path : getAppInfoPlistPaths()) {
    pt::ptree tree;
    auto s = osquery::parsePlist(path, tree);
    if (s.ok()) {
      results.push_back(parseInfoPlist(path, tree));
    } else {
      LOG(ERROR) << "Error parsing " << path << ": " << s.toString();
    }
  }

  return results;
}
}
}
