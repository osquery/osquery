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

const std::vector<std::string> kPackageKeys{
    "name", "version", "description", "license", "homepage"};

void genReadJSONAndAddRow(const std::string& uid,
                          const std::string& package,
                          QueryData& results) {
  std::string json;
  if (!readFile(package, json).ok()) {
    LOG(WARNING) << "Could not read Atom package.json from '" << package << "'";
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    LOG(WARNING) << "Could not parse Atom package.json from " << package << "'";
    return;
  }

  // create row from json and add it to results
  Row r;
  for (const auto& key : kPackageKeys) {
    if (doc.doc().HasMember(key)) {
      const auto& value = doc.doc()[key];
      r[key] = (value.IsString()) ? value.GetString() : "";
    }
  }
  // add package path manually
  r["path"] = package;
  r["uid"] = uid;
  results.push_back(r);
}

QueryData genAtomPackages(QueryContext& context) {
  QueryData results;

  // find atom config directories
  std::set<std::pair<std::string, fs::path>> confDirs;
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto directory = row.find("directory");
    if (directory == row.end() || uid == row.end()) {
      continue;
    }
    confDirs.insert({uid->second, fs::path(directory->second) / ".atom"});
  }

  for (const auto& confDir : confDirs) {
    std::vector<std::string> packages;
    resolveFilePattern(confDir.second / "packages" / "%" / "package.json",
                       packages);
    for (const auto& package : packages) {
      genReadJSONAndAddRow(confDir.first, package, results);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
