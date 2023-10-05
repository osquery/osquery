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
    const rapidjson::Value& identifier = extension["identifier"];
    const rapidjson::Value& metadata = extension["metadata"];
    const rapidjson::Value& location = extension["location"];

    if (identifier.IsObject() && metadata.IsObject()) {
      const rapidjson::Value& id = identifier["id"];
      const rapidjson::Value& version = extension["version"];
      const rapidjson::Value& extensionPath = location["path"];
      const rapidjson::Value& publisherDisplayName =
          metadata["publisherDisplayName"];
      const rapidjson::Value& installedTimestamp =
          metadata["installedTimestamp"];
      const rapidjson::Value& isPreReleaseVersion =
          metadata["isPreReleaseVersion"];

      if (id.IsString() && version.IsString() && extensionPath.IsString() &&
          publisherDisplayName.IsString() && installedTimestamp.IsInt64() &&
          isPreReleaseVersion.IsBool()) {
        Row r;
        r["id"] = id.GetString();
        r["version"] = version.GetString();
        r["path"] = extensionPath.GetString();
        r["publisher"] = publisherDisplayName.GetString();
        r["installed_at"] = std::to_string(installedTimestamp.GetInt64());
        r["prerelease"] = isPreReleaseVersion.GetBool() ? "1" : "0";
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
