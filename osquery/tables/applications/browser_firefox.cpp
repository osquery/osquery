/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <optional>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace fs = boost::filesystem;

namespace osquery {

namespace tables {

namespace {

/// Each home directory will include custom extensions.
#if defined(__APPLE__)
const std::vector<std::string> kFirefoxPaths = {
    "/Library/Application Support/Firefox/Profiles/"};
#elif defined(__linux__)
const std::vector<std::string> kFirefoxPaths = {
    "/.mozilla/firefox/", "/snap/firefox/common/.mozilla/firefox/"};
#elif defined(WIN32)
const std::vector<std::string> kFirefoxPaths = {
    "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"};
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
    {"location", "location"},
    {"path", "path"},
};

bool isMemberTrue(const char* member_name, const rapidjson::Value& from) {
  auto member = from.FindMember(member_name);

  return member != from.MemberEnd() ? JSON::valueToBool(member->value) : false;
}

std::optional<rapidjson::Value::ConstMemberIterator> findNestedMember(
    const std::string& member_name, const rapidjson::Value& value) {
  auto child_members = osquery::split(member_name, ".");

  rapidjson::Value::ConstMemberIterator member_it;
  const rapidjson::Value* current_value = &value;
  for (const auto& child_member : child_members) {
    /* Verify that we are accessing an object at every nested level,
       except the last */
    if (!current_value->IsObject()) {
      return std::nullopt;
    }

    member_it = current_value->FindMember(child_member);

    if (member_it == current_value->MemberEnd()) {
      return std::nullopt;
    }

    current_value = &member_it->value;
  }

  return member_it;
}
} // namespace

void genFirefoxAddonsFromExtensions(const std::string& uid,
                                    const std::string& path,
                                    QueryData& results) {
  JSON extensions;
  Status status;
  std::string extensions_path = path + kFirefoxExtensionsFile;
  {
    std::string content;

    status = readFile(extensions_path, content);
    if (!status.ok()) {
      TLOG << "Failed to read the extensions file at: " << extensions_path
           << ", error: " << status.getMessage();
      return;
    }

    status = extensions.fromString(content);

    if (!status.ok()) {
      TLOG << "Failed to parse to JSON the extensions file at: "
           << extensions_path << ", error: " << status.getMessage();
      return;
    }
  }

  if (!extensions.doc().IsObject()) {
    TLOG << "Failed to parse the JSON extensions file at: " << extensions_path
         << ", the document root is not an object";
    return;
  }

  const auto addons_it = extensions.doc().FindMember("addons");

  if (addons_it == extensions.doc().MemberEnd()) {
    TLOG << "Failed to parse the JSON extensions file at: " << extensions_path
         << ", could not find the 'addons' JSON member";
    return;
  }

  const auto& addons = addons_it->value;

  if (!addons.IsArray()) {
    TLOG << "Unrecognized format for the 'addons' member in the extensions "
            "file at: "
         << extensions_path << ", it's not an array";
    return;
  }

  for (const auto& addon : addons.GetArray()) {
    if (!addon.IsObject()) {
      continue;
    }

    Row r;
    r["uid"] = uid;
    // Most of the keys are in the top-level JSON dictionary.
    for (const auto& it : kFirefoxAddonKeys) {
      const auto opt_member_it = findNestedMember(it.first, addon);

      if (!opt_member_it.has_value()) {
        continue;
      }

      const auto& member_it = *opt_member_it;

      const auto opt_value = JSON::valueToString(member_it->value);
      if (!opt_value.has_value()) {
        TLOG << "Failed to convert member '" << member_it->name.GetString()
             << "' to a string, in JSON extensions file at: "
             << extensions_path;
        continue;
      }

      r[it.second] = SQL_TEXT(*opt_value);
    }

    // There are several ways to disabled the addon, check each.
    if (isMemberTrue("softDisable", addon) ||
        isMemberTrue("appDisabled", addon) ||
        isMemberTrue("userDisabled", addon)) {
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
      // For each user, enumerate all of their Firefox profiles in each path.
      std::vector<std::string> profiles;
      for (const auto& path : kFirefoxPaths) {
        auto directory = fs::path(row.at("directory")) / path;
        if (!listDirectoriesInDirectory(directory, profiles).ok()) {
          continue;
        }
      }

      // Do not list Crash Reports and Pending Pings folders as profiles
      profiles.erase(std::remove_if(profiles.begin(),
                                    profiles.end(),
                                    [](const std::string& s) {
                                      return boost::algorithm::ends_with(
                                                 s, "Crash Reports") ||
                                             boost::algorithm::ends_with(
                                                 s, "Pending Pings");
                                    }),
                     profiles.end());

      // Generate an addons list from their extensions JSON.
      for (const auto& profile : profiles) {
        genFirefoxAddonsFromExtensions(row.at("uid"), profile, results);
      }
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
