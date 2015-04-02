/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Each home directory will include custom extensions.
#ifdef __APPLE__
  #define kFirefoxPath "/Library/Application Support/Firefox/Profiles/"
#else
  #define kFirefoxPath "/.mozilla/firefox/"
#endif

#define kFirefoxExtensionsFile "/extensions.json"

/// Not parsed, but may be helpful later.
#define kFirefoxAddonsFile "/addons.json"
#define kFirefoxWebappsFile "/webapps/webapps.json"

const std::map<std::string, std::string> kFirefoxAddonKeys = {
    {"defaultLocale.name", "name"},
    {"id", "identifier"},
    {"type", "type"},
    {"version", "version"},
    {"defaultLocale.creator", "creator"},
    {"defaultLocale.description", "description"},
    {"sourceURI", "source_url"},
    {"visible", "visible"},
    {"active", "active"},
    {"applyBackgroundUpdates", "autoupdate"},
    {"hasBinaryComponents", "native"},
    {"location", "location"},
    {"descriptor", "path"},
};

void genFirefoxAddonsFromExtensions(const std::string& path,
                                    QueryData& results) {
  std::string json_data;
  if (!readFile(path + kFirefoxExtensionsFile, json_data).ok()) {
    VLOG(1) << "Could not read file: " << path + kFirefoxExtensionsFile;
    return;
  }

  // Read the extensions data into a JSON blob, then property tree.
  pt::ptree tree;
  std::stringstream json_stream;
  json_stream << json_data;
  try {
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    VLOG(1) << "Could not parse JSON from: " << path + kFirefoxExtensionsFile;
    return;
  }

  for (const auto& addon : tree.get_child("addons")) {
    Row r;
    // Most of the keys are in the top-level JSON dictionary.
    for (const auto& it : kFirefoxAddonKeys) {
      try {
        r[it.second] = addon.second.get<std::string>(it.first);
      } catch (const pt::ptree_error& e) {
        r[it.second] = "";
      }

      // Convert bool-types to an integer.
      if (r[it.second] == "true" || r[it.second] == "YES" ||
          r[it.first] == "Yes") {
        r[it.second] = INTEGER(1);
      } else if (r[it.second] == "false" || r[it.second] == "NO" ||
                 r[it.second] == "No") {
        r[it.second] = INTEGER(0);
      }
    }

    // There are several ways to disabled the addon, check each.
    if (addon.second.get<std::string>("softDisable", "false") == "true" ||
        addon.second.get<std::string>("appDisabled", "false") == "true" ||
        addon.second.get<std::string>("userDisabled", "false") == "true") {
      r["disabled"] = INTEGER(1);
    } else {
      r["disabled"] = INTEGER(0);
    }
    results.push_back(r);
  }
}

QueryData genFirefoxAddons(QueryContext& context) {
  QueryData results;

  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    // For each user, enumerate all of their Firefox profiles.
    std::vector<std::string> profiles;
    if (!listDirectoriesInDirectory(home / kFirefoxPath, profiles).ok()) {
      continue;
    }

    // Generate an addons list from their extensions JSON.
    for (const auto& profile : profiles) {
      genFirefoxAddonsFromExtensions(profile, results);
    }
  }

  return results;
}
}
}
