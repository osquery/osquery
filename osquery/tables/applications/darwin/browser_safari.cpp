/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Each home directory will include custom extensions.
#define kSafariExtensionsPath "/Library/Safari/Extensions/"

#define kSafariPluginsPath "/Library/Internet Plug-Ins/"

/// Safari extensions will not load unless they have the expected pattern.
#define kSafariExtensionsPattern "%.safariextz"

const std::map<std::string, std::string> kSafariPluginKeys = {
    {"WebPluginName", "name"},
    {"CFBundleIdentifier", "identifier"},
    {"CFBundleShortVersionString", "version"},
    {"DTPlatformBuild", "sdk"},
    {"WebPluginDescription", "description"},
    {"CFBundleDevelopmentRegion", "development_region"},
    {"LSRequiresNativeExecution", "native"},
};

void genSafariPlugin(const std::string& path, QueryData& results) {
  Row r;
  pt::ptree tree;
  if (osquery::parsePlist(path + "/Contents/Info.plist", tree).ok()) {
    // Plugin did not include an Info.plist, or it was invalid
    for (const auto& it : kSafariPluginKeys) {
      try {
        r[it.second] = tree.get<std::string>(it.first);
      } catch (const pt::ptree_error& e) {
        r[it.second] = "";
      }

      // Convert Plist bool-types to an integer.
      if (r[it.second] == "true" || r[it.second] == "YES" ||
          r[it.first] == "Yes") {
        r[it.second] = INTEGER(1);
      } else if (r[it.second] == "false" || r[it.second] == "NO" ||
                 r[it.second] == "No") {
        r[it.second] = INTEGER(0);
      }
    }
  }

  if (r.at("is_native").size() == 0) {
    // The default case for native execution is false.
    r["is_native"] = "0";
  }

  r["path"] = path;
  results.push_back(r);
}

QueryData genSafariPlugins(QueryContext& context) {
  QueryData results;

  std::vector<std::string> bundles;
  if (listDirectoriesInDirectory(kSafariPluginsPath, bundles).ok()) {
    for (const auto& dir : bundles) {
      genSafariPlugin(dir, results);
    }
  }

  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    bundles.clear();
    if (listDirectoriesInDirectory(home / kSafariPluginsPath, bundles).ok()) {
      for (const auto& dir : bundles) {
        genSafariPlugin(dir, results);
      }
    }
  }

  return results;
}

void genSafariExtension(const std::string& path, QueryData& results) {
  Row r;
  r["name"] = fs::path(path).stem().string();
  r["path"] = path;
  results.push_back(r);
}

QueryData genSafariExtensions(QueryContext& context) {
  QueryData results;

  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    auto dir = home / kSafariExtensionsPath;
    // Check that an extensions directory exists.
    if (!pathExists(dir).ok()) {
      continue;
    }

    // Glob the extension files.
    std::vector<std::string> paths;
    if (!resolveFilePattern(dir / kSafariExtensionsPattern, paths).ok()) {
      continue;
    }

    for (const auto& extension_path : paths) {
      genSafariExtension(extension_path, results);
    }
  }

  return results;
}
}
}
