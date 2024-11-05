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
                                    const std::string& vscode_edition,
                                    QueryData& results) {
  if (!pathExists(path).ok()) {
    return;
  }

  std::string json;
  if (!readFile(path, json).ok()) {
    LOG(INFO) << "Could not read vscode extensions.json from " << path;
    return;
  }

  auto doc = JSON::newArray();
  if (!doc.fromString(json) || !doc.doc().IsArray()) {
    LOG(WARNING) << "Could not parse vscode extensions.json from " << path;
    return;
  }

  for (const rapidjson::Value& extension : doc.doc().GetArray()) {
    if (!(extension.IsObject() && extension.HasMember("identifier") &&
          extension.HasMember("metadata") && extension.HasMember("location"))) {
      LOG(WARNING) << "Extension entry missing expected subkeys in " << path;
      continue;
    }
    const rapidjson::Value& identifier = extension["identifier"];
    const rapidjson::Value& metadata = extension["metadata"];
    const rapidjson::Value& location = extension["location"];
    if (!(identifier.IsObject() && metadata.IsObject() &&
          location.IsObject())) {
      LOG(WARNING) << "Extension subkeys are not objects in " << path;
      continue;
    }

    Row r;
    r["uid"] = uid;
    r["vscode_edition"] = vscode_edition;

    rapidjson::Value::ConstMemberIterator it = identifier.FindMember("id");
    if (it != identifier.MemberEnd() && it->value.IsString()) {
      r["name"] = it->value.GetString();
    }

    it = identifier.FindMember("uuid");
    if (it != identifier.MemberEnd() && it->value.IsString()) {
      r["uuid"] = it->value.GetString();
    }

    it = extension.FindMember("version");
    if (it != extension.MemberEnd() && it->value.IsString()) {
      r["version"] = it->value.GetString();
    }

    it = location.FindMember("path");
    if (it != location.MemberEnd() && it->value.IsString()) {
      r["path"] = it->value.GetString();
    }

    it = metadata.FindMember("publisherDisplayName");
    if (it != metadata.MemberEnd() && it->value.IsString()) {
      r["publisher"] = it->value.GetString();
    }

    it = metadata.FindMember("publisherId");
    if (it != metadata.MemberEnd() && it->value.IsString()) {
      r["publisher_id"] = it->value.GetString();
    }

    it = metadata.FindMember("installedTimestamp");
    if (it != metadata.MemberEnd() && it->value.IsInt64()) {
      r["installed_at"] = INTEGER(it->value.GetInt64());
    }

    it = metadata.FindMember("isPreReleaseVersion");
    if (it != metadata.MemberEnd() && it->value.IsBool()) {
      r["prerelease"] = INTEGER(it->value.GetBool() ? "1" : "0");
    }

    results.push_back(r);
  }
}

struct ConfDir {
  std::string uid;
  fs::path path;
  std::string vscode_edition;

  bool operator<(const ConfDir& other) const {
    return std::tie(uid, path, vscode_edition) <
           std::tie(other.uid, other.path, other.vscode_edition);
  }
};

QueryData genVSCodeExtensions(QueryContext& context) {
  QueryData results;

  // find vscode config directories
  std::set<ConfDir> conf_dirs;
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto directory = row.find("directory");
    if (directory == row.end() || uid == row.end()) {
      continue;
    }

    // Determine the version type and add paths for both VSCode and VSCode
    // Insiders
    conf_dirs.insert(ConfDir{
        uid->second, fs::path(directory->second) / ".vscode-server", "vscode"});
    conf_dirs.insert(ConfDir{
        uid->second, fs::path(directory->second) / ".vscode", "vscode"});
    conf_dirs.insert(
        ConfDir{uid->second,
                fs::path(directory->second) / ".vscode-server-insiders",
                "vscode_insiders"});
    conf_dirs.insert(ConfDir{uid->second,
                             fs::path(directory->second) / ".vscode-insiders",
                             "vscode_insiders"});
  }

  for (const auto& conf_dir : conf_dirs) {
    auto path = conf_dir.path / "extensions" / "extensions.json";
    genReadJSONAndAddExtensionRows(
        conf_dir.uid, path.string(), conf_dir.vscode_edition, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
