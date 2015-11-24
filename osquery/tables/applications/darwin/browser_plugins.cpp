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

/// Include the "external" (not OS X provided) libarchive header.
#include <archive.h>
#include <archive_entry.h>

#include "osquery/tables/applications/browser_utils.h"
#include "osquery/tables/system/system_utils.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Each home directory will include custom extensions.
#define kSafariExtensionsPath "/Library/Safari/Extensions/"

/// Safari extensions will not load unless they have the expected pattern.
#define kSafariExtensionsPattern "%.safariextz"

#define kBrowserPluginsPath "/Library/Internet Plug-Ins/"

const std::map<std::string, std::string> kBrowserPluginKeys = {
    {"WebPluginName", "name"},
    {"CFBundleIdentifier", "identifier"},
    {"CFBundleShortVersionString", "version"},
    {"DTPlatformBuild", "sdk"},
    {"WebPluginDescription", "description"},
    {"CFBundleDevelopmentRegion", "development_region"},
    {"LSRequiresNativeExecution", "native"},
};

const std::map<std::string, std::string> kSafariExtensionKeys = {
    {"CFBundleDisplayName", "name"},
    {"CFBundleIdentifier", "identifier"},
    {"CFBundleShortVersionString", "version"},
    {"Author", "author"},
    {"CFBundleInfoDictionaryVersion", "sdk"},
    {"Description", "description"},
    {"Update Manifest URL", "update_url"},
};

void genBrowserPlugin(const std::string& uid,
                      const std::string& path,
                      QueryData& results) {
  Row r;
  pt::ptree tree;

  r["uid"] = uid;
  if (osquery::parsePlist(path + "/Contents/Info.plist", tree).ok()) {
    // Plugin did not include an Info.plist, or it was invalid
    for (const auto& it : kBrowserPluginKeys) {
      r[it.second] = tree.get(it.first, "");

      // Convert bool-types to an integer.
      jsonBoolAsInt(r[it.second]);
    }
  }

  if (r.count("native") == 0 || r.at("native").size() == 0) {
    // The default case for native execution is false.
    r["native"] = "0";
  }

  r["path"] = path;
  results.push_back(std::move(r));
}

QueryData genBrowserPlugins(QueryContext& context) {
  QueryData results;
  std::vector<std::string> bundles;

  // The caller is not requesting a JOIN against users.
  // This is "special" logic for user data-based tables since there is a concept
  // of system-available browser extensions.
  if (context.constraints["uid"].notExistsOrMatches("0")) {
    std::vector<std::string> bundles;
    if (listDirectoriesInDirectory(kBrowserPluginsPath, bundles).ok()) {
      for (const auto& dir : bundles) {
        genBrowserPlugin("0", dir, results);
      }
    }
  }

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      std::vector<std::string> bundles;
      auto dir = fs::path(row.at("directory")) / kBrowserPluginsPath;
      if (listDirectoriesInDirectory(dir, bundles).ok()) {
        for (const auto& dir : bundles) {
          genBrowserPlugin(row.at("uid"), dir, results);
        }
      }
    }
  }

  return results;
}

inline void genSafariExtension(const std::string& uid,
                               const std::string& path,
                               QueryData& results) {
  Row r;
  r["uid"] = uid;
  r["path"] = path;

  // Loop through (Plist key -> table column name) in kSafariExtensionKeys.
  struct archive* ext = archive_read_new();
  if (ext == nullptr) {
    return;
  }

  // Perform a dry run of the file read.
  if (!readFile(path).ok()) {
    return;
  }

  // Finally drop privileges to the user controlling the extension.
  auto dropper = DropPrivileges::get();
  if (!dropper->dropToParent(path)) {
    return;
  }

  // Use open_file, instead of the preferred open_filename for OS X 10.9.
  archive_read_support_format_xar(ext);
  if (archive_read_open_filename(ext, path.c_str(), 10240) != ARCHIVE_OK) {
    archive_read_finish(ext);
    return;
  }

  struct archive_entry* entry = nullptr;
  while (archive_read_next_header(ext, &entry) == ARCHIVE_OK) {
    auto item_path = archive_entry_pathname(entry);
    // Documentation for libarchive mentions these APIs may return NULL.
    if (item_path == nullptr) {
      archive_read_data_skip(ext);
      continue;
    }

    // Assume there is no non-root Info.
    if (std::string(item_path).find("Info.plist") == std::string::npos) {
      archive_read_data_skip(ext);
      continue;
    }

    // Read the decompressed Info.plist content.
    auto content = std::string(archive_entry_size(entry), '\0');
    archive_read_data_into_buffer(ext, &content[0], content.size());

    // If the Plist can be parsed, extract important keys into columns.
    pt::ptree tree;
    if (parsePlistContent(content, tree).ok()) {
      for (const auto& it : kSafariExtensionKeys) {
        r[it.second] = tree.get(it.first, "");
      }
    }
    break;
  }

  archive_read_close(ext);
  archive_read_finish(ext);
  results.push_back(std::move(r));
}

QueryData genSafariExtensions(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      auto dir = fs::path(row.at("directory")) / kSafariExtensionsPath;
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
        genSafariExtension(row.at("uid"), extension_path, results);
      }
    }
  }

  return results;
}
}
}
