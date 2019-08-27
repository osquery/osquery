/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/logger.h>
#include <osquery/tables/applications/browser_utils.h>
#include <osquery/tables/system/system_utils.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {
namespace {

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
const std::string kProfilePreferencesFile = "Preferences";
const std::string kProfilePreferenceKey = "profile";

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

  // Fetch the permission array from the manifest file
  std::string permission_list;

  const auto& perm_array_obj = tree.get_child_optional(kExtensionPermissionKey);
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

  std::string localized_prefix = "__MSG_";
  Row r;
  r["uid"] = uid;
  r[kExtensionPermissionKey] = permission_list;
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

QueryData genChromeBasedExtensions(QueryContext& context,
                                   const fs::path& sub_dir) {
  QueryData results;

  auto users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      // For each user, enumerate all of their chrome profiles.
      std::vector<std::string> profiles;
      fs::path extension_path = row.at("directory") / sub_dir;
      if (!resolveFilePattern(extension_path, profiles, GLOB_FOLDERS).ok()) {
        continue;
      }

      // For each profile list each extension in the Extensions directory.
      for (const auto& profile : profiles) {
        std::vector<std::string> extensions = {};
        listDirectoriesInDirectory(profile, extensions);

        if (extensions.empty()) {
          continue;
        }

        auto profile_path = fs::path(profile).parent_path().parent_path();

        std::string profile_name;
        auto status = getChromeProfileName(profile_name, profile_path);
        if (!status.ok()) {
          LOG(WARNING) << "Getting Chrome profile name failed: "
                       << status.getMessage();
        }

        // Generate an addons list from their extensions JSON.
        std::vector<std::string> versions;
        for (const auto& extension : extensions) {
          listDirectoriesInDirectory(extension, versions);
        }

        // Extensions use /<EXTENSION>/<VERSION>/manifest.json.
        for (const auto& version : versions) {
          genExtension(row.at("uid"), version, profile_name, results);
        }
      }
    }
  }

  return results;
}
}
}
