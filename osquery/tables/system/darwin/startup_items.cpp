// Copyright 2004-present Facebook. All Rights Reserved.

#include <signal.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <glog/logging.h>

#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kLibraryStartupItemPaths = {
  "/System/Library/StartupItems/",
  "/Library/StartupItems/",
};

/**
 * Find startup items in Library directories
 *
 * Based on
 * https://github.com/synack/knockknock/blob/master/plugins/startupItem.py
 */
void getLibraryStartupItems(QueryData &results) {
  for (std::string dir : kLibraryStartupItemPaths) {
    try {
      for (fs::path potential_dir : fs::directory_iterator(fs::path(dir))) {
        if (fs::is_directory(potential_dir)) {
          fs::path potential_item = potential_dir / potential_dir.filename();
          if (fs::exists(potential_item)
              && fs::is_regular_file(potential_item)) {
            Row r;
            r["name"] = potential_dir.filename().string();
            r["path"] = potential_item.string();
            results.push_back(r);
          }
        }
      }
    } catch (const fs::filesystem_error& e) {
      LOG(ERROR) << "Error traversing " << dir << ":\n" << e.what();
    }
  }
}

/**
 * Parse a Login Items Plist Alias data for bin path
 */
std::string parseAliasData(std::string data) {
  for (int i = 0; i < data.size(); i++) {
    int size = (int) data[i];
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
      return possible_file;
    }

  }
  return "";
}

// Path (after /Users/foo) where the login items plist will be found
const std::string kLoginItemsPlistPath =
  "Library/Preferences/com.apple.loginitems.plist";
// Key to the array within the Login Items plist containing the items
const std::string kLoginItemsKeyPath = "SessionItems.CustomListItems";

/*
 * Get the login items available in System Preferences
 *
 * Based on
 * https://github.com/synack/knockknock/blob/master/plugins/loginItem.py
 */
void getLoginItems(QueryData &results) {
  try {
    for (fs::path home_dir : fs::directory_iterator(fs::path("/Users"))) {
      if (!fs::is_directory(home_dir)) {
        continue;
      }
      pt::ptree tree;
      fs::path plist_path = home_dir / kLoginItemsPlistPath;
      try {
        if (!(fs::exists(plist_path) && fs::is_regular_file(plist_path))) {
          continue;
        }
      } catch (const fs::filesystem_error &e) {
        // Likely permission denied
        VLOG(1) << "Error checking path " << plist_path << ": " << e.what();
        continue;
      }
      Status s = osquery::parsePlist(plist_path.string(), tree);
      if (!s.ok()) {
        LOG(ERROR) << "Error parsing " << plist_path << ": " << s.toString();
        continue;
      }
      // Enumerate Login Items if we successfully opened the plist
      for (auto& entry : tree.get_child(kLoginItemsKeyPath)) {
        std::string name = entry.second.get<std::string>("Name");
        Row r;
        r["name"] = name;
        auto alias_data = entry.second.get<std::string>("Alias");
        try {
          std::string bin_path = parseAliasData(alias_data);
          if (bin_path == "") {
            VLOG(1) << "No valid path found for " << name << " in "
                    << plist_path;
          }
          r["path"] = bin_path;

        } catch (const std::exception& e) {
          LOG(ERROR) << "Error parsing alias data for " << name << " in "
                     << plist_path;
        }
        results.push_back(r);
      }
    }
  } catch (const fs::filesystem_error& e) {
    LOG(ERROR) << "Error traversing home dirs";
  }
}


QueryData genStartupItems() {
  QueryData results;
  getLoginItems(results);
  getLibraryStartupItems(results);
  return results;
}

}
}
