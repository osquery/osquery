/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

extern "C" {
#include <xar/xar.h>
}

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

namespace {

/// A helper check to rename bool-type values as 1 or 0.
inline void jsonBoolAsInt(std::string& s) {
  auto expected = tryTo<bool>(s);
  if (expected.isValue()) {
    s = expected.get() ? "1" : "0";
  }
}

} // namespace

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
    {"DeveloperIdentifier", "developer_id"},
};

void genBrowserPlugin(const std::string& uid,
                      const std::string& path,
                      QueryData& results,
                      bool is_disabled = false) {
  Row r;
  pt::ptree tree;

  r["uid"] = uid;
  auto info_path = path + "/Contents/Info.plist";
  // Ensure that what we're processing is actually a plug-in.
  if (!pathExists(info_path)) {
    return;
  }
  if (osquery::parsePlist(info_path, tree).ok()) {
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
  r["disabled"] = (is_disabled) ? "1" : "0";
  results.push_back(std::move(r));
}

QueryData genBrowserPlugins(QueryContext& context) {
  QueryData results;

  // Lambda to walk through each browser plugin and process the plist file.
  auto enum_browser_plugins = [&results](const fs::path& path,
                                         const std::string& uid) {
    std::vector<std::string> bundles;
    if (listDirectoriesInDirectory(path, bundles).ok()) {
      for (const auto& dir : bundles) {
        genBrowserPlugin(uid, dir, results, false);
      }
    }

    // Check if the plugin is the 'Disabled' folder.
    std::vector<std::string> disabled_bundles;
    auto dis_path = path / "Disabled Plug-Ins";
    if (listDirectoriesInDirectory(dis_path, disabled_bundles).ok()) {
      for (const auto& disabled_dir : disabled_bundles) {
        genBrowserPlugin(uid, disabled_dir, results, true);
      }
    }
  };

  // The caller is not requesting a JOIN against users. This is "special" logic
  // for user data-based tables since there is a concept of system-available
  // browser extensions.
  if (context.constraints["uid"].notExistsOrMatches("0")) {
    enum_browser_plugins(kBrowserPluginsPath, "0");
  }

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      auto dir = fs::path(row.at("directory")) / kBrowserPluginsPath;
      enum_browser_plugins(dir, row.at("uid"));
    }
  }
  return results;
}

inline void genSafariExtension(const std::string& uid,
                               const std::string& gid,
                               const std::string& path,
                               QueryData& results) {
  Row r;
  r["uid"] = uid;
  r["path"] = path;

  // Perform a dry run of the file read.
  if (!isReadable(path).ok()) {
    return;
  }

  // Finally drop privileges to the user controlling the extension.
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo(uid, gid)) {
    VLOG(1) << "Cannot drop privileges to UID " << uid;
    return;
  }

  xar_t xar = xar_open(path.c_str(), READ);
  if (xar == nullptr) {
    TLOG << "Cannot open extension archive: " << path;
    return;
  }

  xar_iter_t iter = xar_iter_new();
  xar_file_t xfile = xar_file_first(xar, iter);

  size_t max_files = 500;
  for (size_t index = 0; index < max_files; ++index) {
    if (xfile == nullptr) {
      break;
    }

    char* xfile_path = xar_get_path(xfile);
    if (xfile_path == nullptr) {
      break;
    }

    // Clean up the allocated content ASAP.
    std::string entry_path(xfile_path);
    free(xfile_path);
    if (entry_path.find("Info.plist") != std::string::npos) {
      if (xar_verify(xar, xfile) != XAR_STREAM_OK) {
        TLOG << "Extension info extraction failed verification: " << path;
      }

      size_t size = 0;
      char* buffer = nullptr;
      if (xar_extract_tobuffersz(xar, xfile, &buffer, &size) != 0 ||
          size == 0) {
        break;
      }

      std::string content(buffer, size);
      free(buffer);

      pt::ptree tree;
      if (parsePlistContent(content, tree).ok()) {
        for (const auto& it : kSafariExtensionKeys) {
          r[it.second] = tree.get(it.first, "");
        }
      }
      break;
    }

    xfile = xar_file_next(iter);
  }

  xar_iter_free(iter);
  xar_close(xar);
  results.push_back(r);
}

QueryData genSafariExtensions(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid == row.end() || gid == row.end() || directory == row.end()) {
      continue;
    }

    auto dir = fs::path(directory->second) / kSafariExtensionsPath;
    // Check that an extensions directory exists.
    if (!pathExists(dir).ok()) {
      continue;
    }

    // Glob the extension files.
    std::vector<std::string> paths;
    if (!resolveFilePattern(
             dir / kSafariExtensionsPattern, paths, GLOB_ALL | GLOB_NO_CANON)
             .ok()) {
      continue;
    }

    for (const auto& extension_path : paths) {
      genSafariExtension(uid->second, gid->second, extension_path, results);
    }
  }

  return results;
}
}
}
