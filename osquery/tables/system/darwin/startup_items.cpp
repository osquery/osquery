// Copyright 2004-present Facebook. All Rights Reserved.

#include <signal.h>

#include "osquery/core.h"
#include "osquery/tables.h"
#include "osquery/filesystem.h"
#include "osquery/logger.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kLibraryStartupItemPaths = {
    "/System/Library/StartupItems/", "/Library/StartupItems/",
};

// Path (after /Users/foo) where the login items plist will be found
const std::string kLoginItemsPlistPath =
    "Library/Preferences/com.apple.loginitems.plist";
// Key to the array within the Login Items plist containing the items
const std::string kLoginItemsKeyPath = "SessionItems.CustomListItems";

/**
 * Find startup items in Library directories
 *
 * Based on
 * https://github.com/synack/knockknock/blob/master/plugins/startupItem.py
 */
void getLibraryStartupItems(QueryData& results) {
  for (const auto& dir : kLibraryStartupItemPaths) {
    fs::directory_iterator it((fs::path(dir))), end;
    try {
      for (; it != end; ++it) {
        if (!fs::exists(it->status()) || !fs::is_directory(it->status())) {
          continue;
        }

        Row r;
        r["name"] = it->path().string();
        r["path"] = it->path().string();
        r["type"] = "Startup Item";
        r["source"] = dir;
        results.push_back(r);
      }
    } catch (const fs::filesystem_error& e) {
      VLOG(1) << "Error traversing " << dir << ": " << e.what();
    }
  }
}

/**
 * Parse a Login Items Plist Alias data for bin path
 */
Status parseAliasData(const std::string& data, std::string& filepath) {
  for (int i = 0; i < data.size(); i++) {
    int size = (int)data[i];
    if (size < 2 || size > data.length() - i) {
      continue;
    }

    std::string possible_file = "/" + data.substr(i + 1, size);
    // This data sometimes contains null bytes. We don't want to consider a
    // path that wasn't the expected length due to null bytes.
    if (strlen(possible_file.c_str()) != size + 1) {
      continue;
    }
    if (fs::exists(possible_file)) {
      filepath = possible_file;
      return Status(0, "OK");
    }
  }
  return Status(1, "No file paths found");
}

/*
 * Get the login items available in System Preferences
 *
 * Based on
 * https://github.com/synack/knockknock/blob/master/plugins/loginItem.py
 */
void getLoginItems(QueryData& results) {
  for (const auto& dir : getHomeDirectories()) {
    pt::ptree tree;
    fs::path plist_path = dir / kLoginItemsPlistPath;
    try {
      if (!fs::exists(plist_path) || !fs::is_regular_file(plist_path)) {
        continue;
      }
    } catch (const fs::filesystem_error& e) {
      // Likely permission denied
      VLOG(1) << "Error checking path " << plist_path << ": " << e.what();
      continue;
    }

    auto status = osquery::parsePlist(plist_path.string(), tree);
    if (!status.ok()) {
      VLOG(1) << "Error parsing " << plist_path << ": " << status.toString();
      continue;
    }

    // Enumerate Login Items if we successfully opened the plist
    for (const auto& entry : tree.get_child(kLoginItemsKeyPath)) {
      Row r;

      auto name = entry.second.get<std::string>("Name");
      r["name"] = name;
      r["type"] = "Login Item";
      r["source"] = plist_path.string();
      auto alias_data = entry.second.get<std::string>("Alias");
      try {
        std::string bin_path;
        if (!parseAliasData(alias_data, bin_path).ok()) {
          VLOG(1) << "No valid path found for " << name << " in " << plist_path;
        }
        r["path"] = bin_path;
      } catch (const std::exception& e) {
        VLOG(1) << "Error parsing alias data for " << name << " in "
                << plist_path;
      }
      results.push_back(r);
    }
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;
  getLoginItems(results);
  getLibraryStartupItems(results);
  return results;
}
}
}
