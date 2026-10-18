/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>

#include <map>
#include <string>
#include <vector>

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

/// Safari App Extensions root directory (top-level apps)
#define kSafariAppExtensionsPath "/Applications/"

/// Safari App Extensions Info.plist glob under a single .app bundle.
/// Relative (no leading slash) so it can be joined onto an .app path.
#define kSafariAppExtensionsPlistRelativePath                                  \
  "Contents/PlugIns/%.appex/Contents/Info.plist"

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

/// Collect Safari .appex metadata from Info.plist paths discovered under
/// @p pattern. @p appex_path is derived as the .appex bundle directory.
inline void collectSafariExtensionsFromPattern(const fs::path& pattern,
                                               SandboxedExtensionsData& data) {
  std::vector<std::string> plist_paths;
  auto status = resolveFilePattern(pattern, plist_paths);
  if (!status.ok()) {
    return;
  }

  for (const auto& plist_path : plist_paths) {
    // .../Something.appex/Contents/Info.plist → .../Something.appex
    const fs::path appex_path =
        fs::path(plist_path).parent_path().parent_path();
    if (isExtensionAppExcluded(appex_path.string())) {
      continue;
    }
    getSandboxedExtensionData(appex_path.string(), plist_path, data);
  }
}

/// Discover Safari App/Web extension bundles under top-level /Applications.
inline void collectSafariExtensionsFromApplications(
    SandboxedExtensionsData& data) {
  if (!pathExists(kSafariAppExtensionsPath).ok()) {
    return;
  }

  std::vector<std::string> app_directories;
  if (!listDirectoriesInDirectory(
          kSafariAppExtensionsPath, app_directories, false)) {
    return;
  }

  for (const auto& app_directory : app_directories) {
    if (isExtensionAppExcluded(app_directory)) {
      continue;
    }
    collectSafariExtensionsFromPattern(
        fs::path(app_directory) / kSafariAppExtensionsPlistRelativePath, data);
  }
}

/// Discover Safari .app bundles under @p root (depth-limited) and collect
/// their PlugIns/*.appex metadata. Prefer finding *.app over listing every
/// file under Application Support (which is huge and can take minutes).
inline void collectSafariExtensionsFromAppBundlesUnder(
    const fs::path& root, SandboxedExtensionsData& data, size_t max_depth) {
  if (max_depth == 0 || !pathExists(root).ok()) {
    return;
  }

  boost::system::error_code ec;
  fs::directory_iterator it(root, ec);
  if (ec) {
    return;
  }
  const fs::directory_iterator end;
  for (; it != end; it.increment(ec)) {
    if (ec) {
      ec.clear();
      continue;
    }
    const auto& entry = *it;
    if (!fs::is_directory(entry.status(ec))) {
      continue;
    }
    const auto name = entry.path().filename().string();
    if (boost::algorithm::ends_with(name, ".app")) {
      if (isExtensionAppExcluded(entry.path().string())) {
        continue;
      }
      collectSafariExtensionsFromPattern(
          entry.path() / kSafariAppExtensionsPlistRelativePath, data);
      // Do not descend into .app bundles.
      continue;
    }
    // Skip common high-churn cache/data trees that never host Safari .appex.
    if (name == "Caches" || name == "logs" || name == "Logs" ||
        name == "CrashReporter" || name == "Code Cache" || name == "GPUCache" ||
        name == "CacheStorage") {
      continue;
    }
    collectSafariExtensionsFromAppBundlesUnder(
        entry.path(), data, max_depth - 1);
  }
}

/// Discover Safari extension bundles under a user's Application Support tree
/// (covers installs such as Webex that are not under /Applications).
///
/// Mid-path `%%`/`**` is not recursive in osquery's globber. Recursively list
/// every file under Application Support is also too expensive (hundreds of
/// thousands of files). Instead, depth-limited directory walk looking only for
/// `*.app` bundles, then reuse the same PlugIns/*.appex pattern as
/// /Applications.
inline void collectSafariExtensionsFromAppSupport(
    const std::string& user_dir, SandboxedExtensionsData& data) {
  auto app_support = fs::path(user_dir) / "Library/Application Support";
  // Depth 8 covers vendor/Add-ons/*.app layouts (e.g. WebEx
  // Folder/Add-ons/...).
  collectSafariExtensionsFromAppBundlesUnder(app_support, data, 8);
}

/// Load Extensions.plist keys once per user (App + Web). Keys are typically
/// "BundleIdentifier (TeamIdentifier)".
inline std::vector<std::string> loadSafariExtensionPlistKeys(
    const fs::path& app_extension_plist, const fs::path& web_extension_plist) {
  std::vector<std::string> keys;
  auto append_keys = [&keys](const fs::path& plist_path) {
    pt::ptree tree;
    if (!getPtreeFromPlist(plist_path, tree)) {
      return;
    }
    for (const auto& entry : tree) {
      keys.push_back(entry.first);
    }
  };
  append_keys(app_extension_plist);
  append_keys(web_extension_plist);
  return keys;
}

inline bool plistKeysContainExtensionIdentifier(
    const std::vector<std::string>& keys, const std::string& identifier) {
  if (identifier.empty()) {
    return false;
  }
  for (const auto& key : keys) {
    if (boost::algorithm::contains(key, identifier)) {
      return true;
    }
  }
  return false;
}

/// Dedupe extension metadata by CFBundleIdentifier, keeping the first-seen
/// path for each identifier.
inline SandboxedExtensionsData dedupeSafariExtensionsByIdentifier(
    const SandboxedExtensionsData& input) {
  SandboxedExtensionsData out;
  std::map<std::string, size_t> index_by_id;
  for (const auto& entry : input) {
    if (entry.identifier.empty()) {
      out.push_back(entry);
      continue;
    }
    auto it = index_by_id.find(entry.identifier);
    if (it == index_by_id.end()) {
      index_by_id[entry.identifier] = out.size();
      out.push_back(entry);
    }
  }
  return out;
}

/// Merge per-user Application Support discoveries with /Applications,
/// preferring /Applications for the same CFBundleIdentifier. App Support is
/// merged per user so two users with the same identifier keep their own paths.
inline SandboxedExtensionsData mergePreferringApplications(
    const SandboxedExtensionsData& applications,
    const SandboxedExtensionsData& app_support) {
  auto out = dedupeSafariExtensionsByIdentifier(applications);
  std::map<std::string, size_t> index_by_id;
  for (size_t i = 0; i < out.size(); ++i) {
    if (!out[i].identifier.empty()) {
      index_by_id[out[i].identifier] = i;
    }
  }
  for (const auto& entry : app_support) {
    if (entry.identifier.empty()) {
      out.push_back(entry);
      continue;
    }
    if (index_by_id.find(entry.identifier) == index_by_id.end()) {
      index_by_id[entry.identifier] = out.size();
      out.push_back(entry);
    }
  }
  return out;
}

inline void genSafariSandboxedExtensions(const QueryContext& context,
                                         QueryData& results) {
  // Returning if there is no user context information
  auto users = usersFromContext(context);
  if (users.empty()) {
    return;
  }

  // Discover sandboxed Safari extension bundles, then match them against each
  // user's AppExtensions/WebExtensions registration plists. Discovery covers:
  //   1) top-level /Applications/*.app (classic location; shared)
  //   2) each queried user's ~/Library/Application Support tree (e.g. Webex)
  // Matching still requires the extension to appear in the user's Safari
  // Extensions.plist (plist registration is authoritative for "installed for
  // this user"; disk scan supplies metadata/path).
  SandboxedExtensionsData applications;
  collectSafariExtensionsFromApplications(applications);
  applications = dedupeSafariExtensionsByIdentifier(applications);

  for (const auto& row : users) {
    auto uid = row.at("uid");
    auto user_dir = row.at("directory");

    // Sanity check / skip non-user queries
    if (uid.empty() || user_dir.empty() ||
        !boost::algorithm::starts_with(user_dir, "/Users")) {
      continue;
    }

    SandboxedExtensionsData app_support;
    collectSafariExtensionsFromAppSupport(user_dir, app_support);
    auto candidates = mergePreferringApplications(applications, app_support);
    if (candidates.empty()) {
      continue;
    }

    // Parse each user's Extensions.plist once (not once per candidate).
    const auto plist_keys = loadSafariExtensionPlistKeys(
        fs::path(user_dir) / kAppExtensionsPlistPath,
        fs::path(user_dir) / kWebExtensionsPlistPath);

    for (const auto& extension_data : candidates) {
      if (!plistKeysContainExtensionIdentifier(plist_keys,
                                               extension_data.identifier)) {
        continue;
      }
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
