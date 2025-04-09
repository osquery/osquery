/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>

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

/// Safari Extension Point Identifier
#define kSafariExtensionPointIdentifier "com.apple.Safari"

/// Safari App Extensions root directory
#define kSafariAppExtensionsPath "/Applications/"

/// Safari App Extensions Plist path
#define kSafariAppExtensionsPlistPath                                          \
  "/Contents/PlugIns/%.appex/Contents/Info.plist"

/// User Safari extension path
#define kUserSafariExtensionsPath                                              \
  "/Library/Containers/com.apple.Safari/Data/Library/Safari"

/// User Safari extension path for App Extensions
#define kAppExtensionsPlistPath                                                \
  kUserSafariExtensionsPath "/AppExtensions/Extensions.plist"

/// User Safari extension path for Web Extensions
#define kWebExtensionsPlistPath                                                \
  kUserSafariExtensionsPath "/WebExtensions/Extensions.plist"

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

struct SandboxedExtensionData {
  /// Extension Name
  std::string name;

  /// Extension Identifier
  std::string identifier;

  /// Extension Version
  std::string version;

  /// Extension SDK Version
  std::string sdk;

  /// Parent App
  std::string app_path;

  /// Human Readable Description
  std::string hr_description;

  /// CF Bundle Version
  std::string cf_bundle_version;

  /// NS Human Readable Copyright
  std::string ns_hr_copyright;
};

using SandboxedExtensionsData = std::vector<SandboxedExtensionData>;

const std::vector<std::string> kExtensionsAppDirsToExclude = {
    "/Xcode.app",
    "/Safari.app",
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

inline bool getPtreeFromPlist(const fs::path& plist_path, pt::ptree& tree) {
  // Perform a dry run of the file read.
  if (!isReadable(plist_path).ok()) {
    return false;
  }

  // Read the plist file
  std::string content;
  if (!readFile(plist_path, content).ok()) {
    return false;
  }

  // Parse the plist content
  if (!parsePlistContent(content, tree).ok()) {
    return false;
  }

  return true;
}

inline void getSandboxedExtensionData(const std::string& extension_path,
                                      const std::string& plist_path,
                                      SandboxedExtensionsData& data) {
  // Parse the plist content
  pt::ptree tree;
  if (!getPtreeFromPlist(plist_path, tree)) {
    TLOG << "Ptree parsing failed: " << plist_path;
    return;
  }

  // Populating SandboxedExtensionData entry
  SandboxedExtensionData entry;

  // Checking first if this is a Safari extension by looking into NSExtension
  if (tree.count("NSExtension") == 0) {
    return;
  }

  const auto& extensionIdentifier =
      tree.get_child("NSExtension")
          .get<std::string>("NSExtensionPointIdentifier", "");

  if (!boost::algorithm::contains(extensionIdentifier,
                                  kSafariExtensionPointIdentifier)) {
    return;
  }

  // We found a Safari extension! Let's extract its metadata
  entry.app_path = extension_path;
  entry.identifier = tree.get<std::string>("CFBundleIdentifier", "");
  entry.name = tree.get<std::string>("CFBundleDisplayName", "");
  entry.sdk = tree.get<std::string>("CFBundleInfoDictionaryVersion", "");
  entry.version = tree.get<std::string>("CFBundleShortVersionString", "");
  entry.cf_bundle_version = tree.get<std::string>("CFBundleVersion", "");
  entry.ns_hr_copyright = tree.get<std::string>("NSHumanReadableCopyright", "");
  entry.hr_description =
      tree.get<std::string>("NSHumanReadableDescription", "");

  data.push_back(entry);
}

inline bool isExtensionAppExcluded(const std::string& app_dir) {
  if (app_dir.empty()) {
    return false;
  }

  for (const auto& app_to_exclude : kExtensionsAppDirsToExclude) {
    if (boost::algorithm::contains(app_dir, app_to_exclude)) {
      return true;
    }
  }

  return false;
}

inline bool isUserExtension(const fs::path& app_extension_plist,
                            const fs::path web_extension_plist,
                            const SandboxedExtensionData& ext_data) {
  // Gather user extension metainformation
  pt::ptree app_extension_ptree;
  pt::ptree web_extension_ptree;

  // Iterate over the list of user extensions and check if there is a match with
  // extension identifier
  getPtreeFromPlist(app_extension_plist, app_extension_ptree);
  for (const auto& entry : app_extension_ptree) {
    if (boost::algorithm::contains(entry.first, ext_data.identifier)) {
      return true;
    }
  }

  getPtreeFromPlist(web_extension_plist, web_extension_ptree);
  for (const auto& entry : web_extension_ptree) {
    if (boost::algorithm::contains(entry.first, ext_data.identifier)) {
      return true;
    }
  }

  return false;
}

inline void genSafariSandboxedExtensions(const QueryContext& context,
                                         QueryData& results) {
  // Returning if there is no user context information
  auto users = usersFromContext(context);
  if (users.empty()) {
    return;
  }

  // We need to get the sandboxed extension data first

  // Checking that an extensions directory exists
  if (!pathExists(kSafariAppExtensionsPath).ok()) {
    return;
  }

  // Getting app directories
  std::vector<std::string> app_directories;
  if (!listDirectoriesInDirectory(
          kSafariAppExtensionsPath, app_directories, false)) {
    return;
  }

  // Traverse app directories to obtain app extension data if present
  SandboxedExtensionsData sandboxed_ext_data;
  for (auto& app_directory : app_directories) {
    if (isExtensionAppExcluded(app_directory)) {
      continue;
    }

    // Grabbing the extension plist metadata if present
    std::vector<std::string> plist_paths;
    boost::filesystem::path pattern(
        app_directory.append(kSafariAppExtensionsPlistPath));
    auto status = resolveFilePattern(pattern, plist_paths);
    if (status.ok()) {
      for (const auto& plist_path : plist_paths) {
        getSandboxedExtensionData(
            app_directory, plist_path, sandboxed_ext_data);
      }
    }
  }

  // Return if no sandboxed extensions were found - No extensions installed
  if (sandboxed_ext_data.empty()) {
    return;
  }

  // We have the sandboxed extension metainformation, we now need to check
  // if extensions were installed by a given user

  // Iterating over provided user context
  for (const auto& row : users) {
    auto uid = row.at("uid");
    auto user_dir = row.at("directory");

    // Sanity check
    if (uid.empty() || user_dir.empty()) {
      continue;
    }

    // Skipping non-user queries
    if (!boost::algorithm::starts_with(user_dir, "/Users")) {
      continue;
    }

    auto user_app_extensions_plist =
        fs::path(user_dir) / kAppExtensionsPlistPath;

    auto user_web_extensions_plist =
        fs::path(user_dir) / kWebExtensionsPlistPath;

    // Check if app extension was installed by a given user
    for (const auto& extension_data : sandboxed_ext_data) {
      if (isUserExtension(user_app_extensions_plist,
                          user_web_extensions_plist,
                          extension_data)) {
        // Populate the extension entry if found
        Row r;
        r["uid"] = uid;
        r["name"] = extension_data.name;
        r["identifier"] = extension_data.identifier;
        r["version"] = extension_data.version;
        r["sdk"] = extension_data.sdk;
        r["path"] = extension_data.app_path;
        r["bundle_version"] = extension_data.cf_bundle_version;
        r["copyright"] = extension_data.ns_hr_copyright;
        r["description"] = extension_data.hr_description;
        results.push_back(r);
      }
    }
  }
}

QueryData genSafariExtensions(QueryContext& context) {
  QueryData results;

  // Getting Sandboxed Safari Extensions metainformation
  // Logic is capable of extracting metainformation from Safari Web extensions
  // and Safari App Extensions models.
  // This logic requires Full Disk Access (FDA) rights.
  genSafariSandboxedExtensions(context, results);

  return results;
}

} // namespace tables
} // namespace osquery
