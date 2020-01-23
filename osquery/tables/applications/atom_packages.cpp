/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <pwd.h>
#include <set>
#include <string>
#include <sys/types.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::vector<std::string> kPackageKeys{
    "name", "version", "description", "license", "homepage"};

void genReadJSONAndAddRow(const std::string& package, QueryData& results) {
  std::string json;
  if (!readFile(package, json).ok()) {
    LOG(WARNING) << "Could not read Atom's package.json from '" << package
                 << "'";
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    LOG(WARNING) << "Could not parse Atom's package.json from " << package
                 << "'";
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
  results.push_back(r);
}

QueryData genAtomPackages(QueryContext& context) {
  QueryData results;
  // find atom config directories
  std::set<fs::path> confDirs;
  struct passwd* pwd;
  while ((pwd = getpwent()) != NULL) {
    fs::path confDir{pwd->pw_dir};
    confDir /= ".atom";
    if (isDirectory(confDir)) {
      confDirs.insert(confDir);
    }
  }

  for (const auto& confDir : confDirs) {
    std::vector<std::string> packages;
    resolveFilePattern(confDir / "packages" / "%" / "package.json", packages);
    for (const auto& package : packages) {
      genReadJSONAndAddRow(package, results);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
