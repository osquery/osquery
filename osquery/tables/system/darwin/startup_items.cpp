/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"

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
const std::vector<std::string> kLoginItemsKeyPaths = {
    "SessionItems.CustomListItems", "privilegedlist.CustomListItems",
};

void genLibraryStartupItems(const std::string& sysdir, QueryData& results) {
  try {
    fs::directory_iterator it((fs::path(sysdir))), end;
    for (; it != end; ++it) {
      if (!fs::exists(it->status()) || !fs::is_directory(it->status())) {
        continue;
      }

      Row r;
      r["name"] = it->path().string();
      r["path"] = it->path().string();
      r["type"] = "Startup Item";
      r["source"] = sysdir;
      results.push_back(r);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << sysdir << ": " << e.what();
  }
}

/// Parse a Login Items Plist Alias data for bin path
Status parseAliasData(const std::string& data, std::string& result) {
  auto decoded = base64Decode(data);
  if (decoded.size() == 0) {
    // Base64 encoded data (from plist parsing) failed to decode.
    return Status(1, "Failed base64 decode");
  }

  auto alias = CFDataCreate(
      kCFAllocatorDefault, (const UInt8*)decoded.c_str(), decoded.size());
  if (alias == nullptr) {
    // Failed to create CFData object.
    return Status(2, "CFData allocation failed");
  }

  auto bookmark =
      CFURLCreateBookmarkDataFromAliasRecord(kCFAllocatorDefault, alias);
  if (bookmark == nullptr) {
    CFRelease(alias);
    return Status(1, "Alias data is not a bookmark");
  }

  auto url = CFURLCreateByResolvingBookmarkData(
      kCFAllocatorDefault, bookmark, 0, nullptr, nullptr, nullptr, nullptr);
  if (url == nullptr) {
    CFRelease(alias);
    CFRelease(bookmark);
    return Status(1, "Alias data is not a URL bookmark");
  }

  // Get the URL-formatted path.
  result = stringFromCFString(CFURLGetString(url));
  if (result.substr(0, 7) == "file://") {
    result = result.substr(7);
  }

  CFRelease(alias);
  CFRelease(bookmark);
  CFRelease(url);
  return Status(0, "OK");
}

void genLoginItems(const fs::path& homedir, QueryData& results) {
  pt::ptree tree;
  fs::path sipath = homedir / kLoginItemsPlistPath;
  if (!pathExists(sipath.string()).ok() || !isReadable(sipath.string()).ok()) {
    // User does not have a startup items list, or bad permissions.
    return;
  }

  if (!osquery::parsePlist(sipath.string(), tree).ok()) {
    // Could not parse the user's startup items plist.
    return;
  }

  // Enumerate Login Items if we successfully opened the plist.
  for (const auto& plist_path : kLoginItemsKeyPaths) {
    try {
      for (const auto& entry : tree.get_child(plist_path)) {
        Row r;
        r["name"] = entry.second.get<std::string>("Name", "");
        r["type"] = "Login Item";
        r["source"] = sipath.string();

        auto alias_data = entry.second.get<std::string>("Alias", "");
        std::string bin_path;
        if (!parseAliasData(alias_data, bin_path).ok()) {
          VLOG(1) << "No valid path found for " << r["name"] << " in "
                  << sipath;
        }
        r["path"] = bin_path;
        results.push_back(r);
      }
    } catch (const pt::ptree_error& e) {
      VLOG(2) << "Failed to retrieve plist entry: " << e.what();
      continue;
    }
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // Get the login items available for all users
  genLoginItems("/", results);

  // Get the login items available in System Preferences for each user.
  for (const auto& dir : getHomeDirectories()) {
    genLoginItems(dir, results);
  }

  // Find system wide startup items in Library directories.
  for (const auto& dir : kLibraryStartupItemPaths) {
    genLibraryStartupItems(dir, results);
  }

  return results;
}
}
}
