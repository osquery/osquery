/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/logger/logger.h>
#include <osquery/tables/applications/browser_utils.h>
#include <osquery/tables/system/system_utils.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {
namespace {

using ChromeExtensionContentScriptMap =
    std::map<std::tuple<std::string, std::string>,
             std::set<std::tuple<std::string, std::string>>>;

using ChromeContentScriptDetails =
    std::vector<std::map<std::string, std::vector<std::string>>>;

using ChromeUserExtensions =
    std::tuple<std::string /* uid */,
               std::vector<std::string> /* extension_paths*/>;

#define kManifestFile "/manifest.json"

const std::map<std::string, std::string> kExtensionKeys = {
    {"version", "version"},
    {"name", "name"},
    {"description", "description"},
    {"default_locale", "locale"},
    {"update_url", "update_url"},
    {"author", "author"},
    {"background.persistent", "persistent"}};

const std::string kExtensionPermissionKey = "permissions";
const std::string kExtensionOptionalPermissionKey = "optional_permissions";
const std::string kProfilePreferencesFile = "Preferences";
const std::string kProfilePreferenceKey = "profile";
const std::string kScriptKey = "js";
const std::string kMatchesKey = "matches";

std::vector<ChromeUserExtensions> chromeExtensionPathsByUser(
    const QueryData& users, const std::vector<fs::path>& chromePaths) {
  std::vector<ChromeUserExtensions> extensionPathsByUser;

  for (const auto& row : users) {
    if (row.count("uid") == 0 || row.count("directory") == 0) {
      continue;
    }

    // For each user, enumerate all of their chrome profiles.
    for (const auto& chromePath : chromePaths) {
      std::vector<std::string> profiles;
      fs::path extension_path = row.at("directory") / chromePath;
      if (!resolveFilePattern(extension_path, profiles, GLOB_FOLDERS).ok()) {
        continue;
      }

      // For each profile list each extension in the Extensions directory.
      for (const auto& profile : profiles) {
        std::vector<std::string> unversionedExtensions = {};
        listDirectoriesInDirectory(profile, unversionedExtensions);

        if (unversionedExtensions.empty()) {
          continue;
        }
        std::vector<std::string> extensionPaths;
        for (const auto& unversionedExtension : unversionedExtensions) {
          listDirectoriesInDirectory(unversionedExtension, extensionPaths);
        }

        extensionPathsByUser.push_back(
            std::make_tuple(row.at("uid"), extensionPaths));
      }
    }
  }

  return extensionPathsByUser;
}

Status getChromeProfileName(std::string& name, const fs::path& path) {
  name.clear();

  std::string json_data;
  if (!forensicReadFile(path / kProfilePreferencesFile, json_data).ok()) {
    return Status::failure("Failed to read the Preferences file for profile " +
                           path.string());
  }

  pt::ptree tree;
  try {
    std::stringstream json_stream;
    json_stream << json_data;
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error&) {
    return Status::failure("Failed to parse the Preferences file for profile " +
                           path.string());
  }

  const auto& profile_obj = tree.get_child_optional(kProfilePreferenceKey);
  if (!profile_obj) {
    return Status::failure("The following profile is malformed: " +
                           path.string());
  }

  name = profile_obj.get().get<std::string>("name", "");
  if (name.empty()) {
    return Status::failure("The following profile has no name: " +
                           path.string());
  }

  return Status::success();
}
} // namespace

const std::string genPermissions(const std::string& permissionTypeKey,
                                 const pt::ptree& tree) {
  std::string permission_list;

  const auto& perm_array_obj = tree.get_child_optional(permissionTypeKey);
  if (perm_array_obj) {
    const auto& perm_array_contents = perm_array_obj.get();

    std::vector<std::string> perm_vector;
    perm_vector.reserve(perm_array_contents.size());

    for (auto it = perm_array_contents.begin(); it != perm_array_contents.end();
         ++it) {
      const auto& perm_obj = *it;
      const auto& permission =
          perm_obj.second.get_value_optional<std::string>();
      if (permission) {
        perm_vector.emplace_back(*permission);
      }
    }

    permission_list = boost::algorithm::join(perm_vector, ", ");
  }
  return permission_list;
}

ChromeContentScriptDetails genContentScriptDetail(const pt::ptree& tree) {
  ChromeContentScriptDetails details;

  if (const auto& content_script_array =
          tree.get_child_optional("content_scripts")) {
    for (const auto& content_script : content_script_array.get()) {
      std::map<std::string, std::vector<std::string>> detail;

      if (const auto& js_script_array =
              content_script.second.get_child_optional(kScriptKey)) {
        for (const auto& js_script : js_script_array.get()) {
          if (const auto& js_script_value =
                  js_script.second.get_value_optional<std::string>()) {
            detail[kScriptKey].push_back(js_script_value.get());
          }
        }
      }

      if (const auto& match_array =
              content_script.second.get_child_optional(kMatchesKey)) {
        for (const auto& match : match_array.get()) {
          if (const auto& match_value =
                  match.second.get_value_optional<std::string>()) {
            detail[kMatchesKey].push_back(match_value.get());
          }
        }
      }

      details.push_back(detail);
    }
  }

  return details;
}

void genExtension(const std::string& uid,
                  const std::string& path,
                  const std::string& profile_name,
                  QueryData& results) {
  std::string json_data;
  if (!forensicReadFile(path + kManifestFile, json_data).ok()) {
    VLOG(1) << "Could not read file: " << path + kManifestFile;
    return;
  }

  // Read the extension metadata into a JSON blob, then property tree.
  pt::ptree tree;
  try {
    std::stringstream json_stream;
    json_stream << json_data;
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    VLOG(1) << "Could not parse JSON from: " << path + kManifestFile;
    return;
  }

  pt::iptree messagetree;
  // Find out if there are localized values for fields
  if (!tree.get<std::string>("default_locale", "").empty()) {
    // Read the localized variables into a second ptree
    std::string messages_json;
    std::string localized_path = path + "/_locales/" +
                                 tree.get<std::string>("default_locale") +
                                 "/messages.json";
    if (!forensicReadFile(localized_path, messages_json).ok()) {
      VLOG(1) << "Could not read file: " << localized_path;
      return;
    }

    try {
      std::stringstream messages_stream;
      messages_stream << messages_json;
      pt::read_json(messages_stream, messagetree);
    } catch (const pt::json_parser::json_parser_error& /* e */) {
      VLOG(1) << "Could not parse JSON from: " << localized_path;
      return;
    }
  }

  std::string localized_prefix = "__MSG_";
  Row r;
  r["uid"] = uid;
  r[kExtensionPermissionKey] = genPermissions(kExtensionPermissionKey, tree);
  r[kExtensionOptionalPermissionKey] =
      genPermissions(kExtensionOptionalPermissionKey, tree);
  r["profile"] = profile_name;
  // Most of the keys are in the top-level JSON dictionary.
  for (const auto& it : kExtensionKeys) {
    std::string key = tree.get<std::string>(it.first, "");
    // If the value is an i18n reference, grab referenced value
    if (key.compare(0, localized_prefix.length(), localized_prefix) == 0 &&
        key.length() > 8) {
      r[it.second] = messagetree.get<std::string>(
          key.substr(6, key.length() - 8) + ".message", key);
    } else {
      r[it.second] = key;
    }
    // Convert JSON bool-types to an integer.
    if (r[it.second] == "true") {
      r[it.second] = INTEGER(1);
    } else if (r[it.second] == "false") {
      r[it.second] = INTEGER(0);
    }
  }

  // Set the default persistence setting to false
  if (r.at("persistent") == "") {
    r["persistent"] = INTEGER(0);
  }

  r["identifier"] = fs::path(path).parent_path().parent_path().leaf().string();
  r["path"] = path;

  results.push_back(r);
}

void genExtensionContentScripts(
    const std::string& path,
    ChromeExtensionContentScriptMap& contentScriptMap) {
  std::string json_data;
  if (!forensicReadFile(path + kManifestFile, json_data).ok()) {
    VLOG(1) << "Could not read file: " << path + kManifestFile;
    return;
  }

  // Read the extension metadata into a JSON blob, then property tree.
  pt::ptree tree;
  try {
    std::stringstream json_stream;
    json_stream << json_data;
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    VLOG(1) << "Could not parse JSON from: " << path + kManifestFile;
    return;
  }

  const std::string& version = tree.get<std::string>("version", "");
  auto& scriptMatchPairs = contentScriptMap[std::make_tuple(
      fs::path(path).parent_path().parent_path().leaf().string(), version)];

  auto contentScriptDetail = genContentScriptDetail(tree);
  for (auto& contentScript : contentScriptDetail) {
    for (auto& script : contentScript[kScriptKey]) {
      if (contentScript[kMatchesKey].empty()) {
        scriptMatchPairs.insert(std::make_tuple(script, ""));
      } else {
        for (auto& match : contentScript[kMatchesKey]) {
          scriptMatchPairs.insert(std::make_tuple(script, match));
        }
      }
    }
  }
}

QueryData genChromeBasedExtensions(QueryContext& context,
                                   const std::vector<fs::path>& chromePaths) {
  QueryData results;

  const auto& extensionPathsByUser =
      chromeExtensionPathsByUser(usersFromContext(context), chromePaths);

  for (const auto& userExtensionPaths : extensionPathsByUser) {
    const auto& uid = std::get<0>(userExtensionPaths);
    std::map<fs::path, std::string> profileNameMap;

    for (const auto& version : std::get<1>(userExtensionPaths)) {
      const auto& profile_path = fs::path(version)
                                     .parent_path()
                                     .parent_path()
                                     .parent_path()
                                     .parent_path();

      auto it = profileNameMap.find(profile_path);
      if (it == profileNameMap.end()) {
        auto status =
            getChromeProfileName(profileNameMap[profile_path], profile_path);
        if (!status.ok()) {
          LOG(WARNING) << "Getting Chrome profile name failed: "
                       << status.getMessage();
        }
      }

      genExtension(uid, version, profileNameMap[profile_path], results);
    }
  }

  return results;
}

QueryData genChromeBasedExtensionContentScripts(
    QueryContext& context, const std::vector<fs::path>& chromePaths) {
  QueryData results;

  // Extensions are frequently duplicated across profiles and
  // Chrome installations, so we construct a map of
  // (extension_id, version) -> {(script, match)}
  // for deduplication purposes.
  ChromeExtensionContentScriptMap contentScriptMap;

  const auto& extensionPathsByUser =
      chromeExtensionPathsByUser(usersFromContext(context), chromePaths);
  for (const auto& userExtensionPaths : extensionPathsByUser) {
    for (const auto& version : std::get<1>(userExtensionPaths)) {
      genExtensionContentScripts(version, contentScriptMap);
    }
  }

  for (const auto& it : contentScriptMap) {
    Row r;

    r["identifier"] = std::get<0>(it.first);
    r["version"] = std::get<1>(it.first);

    for (const auto& scriptMatchPair : it.second) {
      r["script"] = std::get<0>(scriptMatchPair);
      r["match"] = std::get<1>(scriptMatchPair);
      results.push_back(r);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
