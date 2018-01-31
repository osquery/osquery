/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/applications/browser_utils.h"
#include "osquery/tables/system/system_utils.h"

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

void genFirefoxAddonsFromExtensions(const std::string& uid,
                                    const std::string& path,
                                    QueryData& results) {
  pt::ptree tree;
  if (!osquery::parseJSON(path + kFirefoxExtensionsFile, tree).ok()) {
    TLOG << "Could not parse JSON from: " << path + kFirefoxExtensionsFile;
    return;
  }

  for (const auto& addon : tree.get_child("addons")) {
    Row r;
    r["uid"] = uid;
    // Most of the keys are in the top-level JSON dictionary.
    for (const auto& it : kFirefoxAddonKeys) {
      r[it.second] = addon.second.get(it.first, "");

      // Convert bool-types to an integer.
      jsonBoolAsInt(r[it.second]);
    }

    // There are several ways to disabled the addon, check each.
    if (addon.second.get("softDisable", "false") == "true" ||
        addon.second.get("appDisabled", "false") == "true" ||
        addon.second.get("userDisabled", "false") == "true") {
      r["disabled"] = INTEGER(1);
    } else {
      r["disabled"] = INTEGER(0);
    }
    results.push_back(r);
  }
}

QueryData genFirefoxAddons(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      // For each user, enumerate all of their Firefox profiles.
      std::vector<std::string> profiles;
      auto directory = fs::path(row.at("directory")) / kFirefoxPath;
      if (!listDirectoriesInDirectory(directory, profiles).ok()) {
        continue;
      }

      // Generate an addons list from their extensions JSON.
      for (const auto& profile : profiles) {
        genFirefoxAddonsFromExtensions(row.at("uid"), profile, results);
      }
    }
  }

  return results;
}
}
}
