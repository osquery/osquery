/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>
#include <string>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

namespace {
std::string getStringValuefromRjObject(const rapidjson::Value& obj,
                                       const std::string& key) {
  rapidjson::Value::ConstMemberIterator itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    const rapidjson::Value& value = itr->value;

    if (value.IsString()) {
      return value.GetString();
    }

    if (value.IsInt64()) {
      return std::to_string(value.GetInt64());
    }

    if (value.IsBool()) {
      return value.GetBool() ? "1" : "0";
    }
  }

  return "";
}
} // namespace

void genReadJSONAndAddExtensionRows(const std::string& uid,
                                    const std::string& path,
                                    QueryData& results) {
  std::string json;
  if (!readFile(path, json).ok()) {
    LOG(WARNING) << "Could not read vscode extensions.json from '" << path
                 << "'";
    return;
  }

  auto doc = JSON::newArray();
  if (!doc.fromString(json) || !doc.doc().IsArray()) {
    LOG(WARNING) << "Could not parse vscode extensions.json from " << path
                 << "'";
    return;
  }

  rapidjson::Value::ConstValueIterator itr;
  for (itr = doc.doc().Begin(); itr != doc.doc().End(); ++itr) {
    const rapidjson::Value& extension = *itr;

    if (!(extension.IsObject() && extension.HasMember("identifier") &&
          extension.HasMember("metadata") && extension.HasMember("location"))) {
      continue;
    }

    const rapidjson::Value& identifier = extension["identifier"];
    const rapidjson::Value& metadata = extension["metadata"];
    const rapidjson::Value& location = extension["location"];

    if (identifier.IsObject() && metadata.IsObject() && location.IsObject()) {
      std::string id = getStringValuefromRjObject(identifier, "id");

      if (id != "") {
        Row r;

        r["id"] = id;
        r["version"] = getStringValuefromRjObject(extension, "version");
        r["path"] = getStringValuefromRjObject(location, "path");
        r["publisher"] =
            getStringValuefromRjObject(metadata, "publisherDisplayName");
        r["installed_at"] =
            getStringValuefromRjObject(metadata, "installedTimestamp");
        r["prerelease"] =
            getStringValuefromRjObject(metadata, "isPreReleaseVersion");
        r["uid"] = uid;
        results.push_back(r);
      }
    }
  }
}

QueryData genVSCodeExtensions(QueryContext& context) {
  QueryData results;

  // find vscode config directories
  std::set<std::pair<std::string, fs::path>> confDirs;
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto directory = row.find("directory");
    if (directory == row.end() || uid == row.end()) {
      continue;
    }
    confDirs.insert(
        {uid->second, fs::path(directory->second) / ".vscode-server"});
    confDirs.insert({uid->second, fs::path(directory->second) / ".vscode"});
  }

  for (const auto& confDir : confDirs) {
    auto path = confDir.second / "extensions" / "extensions.json";
    genReadJSONAndAddExtensionRows(confDir.first, path.string(), results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
