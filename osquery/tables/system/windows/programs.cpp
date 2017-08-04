/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

void keyEnumPrograms(const std::string& key,
                     std::set<std::string>& processed,
                     QueryData& results) {
  QueryData regResults;
  queryKey(key, regResults);
  for (const auto& rKey : regResults) {
    if (rKey.at("type") != "subkey") {
      continue;
    }
    QueryData appResults;
    const auto& subkey = rKey.at("path");
    // make sure it's a sane uninstall key
    boost::smatch matches;
    boost::regex expression(
        "({[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+})"
        "$");
    if (!boost::regex_search(subkey, matches, expression)) {
      continue;
    }
    // Ensure we only process a program once
    auto processGuid = matches[0];
    if (processed.find(processGuid) != processed.end()) {
      continue;
    }
    processed.insert(processGuid);
    queryKey(subkey, appResults);
    Row r;
    r["identifying_number"] = processGuid;
    for (const auto& aKey : appResults) {
      if (aKey.at("name") == "DisplayName") {
        r["name"] = aKey.at("data");
      }
      if (aKey.at("name") == "DisplayVersion") {
        r["version"] = aKey.at("data");
      }
      if (aKey.at("name") == "InstallSource") {
        r["install_source"] = aKey.at("data");
      }
      if (aKey.at("name") == "Language") {
        r["language"] = aKey.at("data");
      }
      if (aKey.at("name") == "Publisher") {
        r["publisher"] = aKey.at("data");
      }
      if (aKey.at("name") == "UninstallString") {
        r["uninstall_string"] = aKey.at("data");
      }
      if (aKey.at("name") == "InstallDate") {
        r["install_date"] = aKey.at("data");
      }
    }
    results.push_back(r);
  }
}

QueryData genPrograms(QueryContext& context) {
  QueryData results;

  std::set<std::string> programKeys = {
      "HKEY_LOCAL_"
      "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
      "HKEY_LOCAL_"
      "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Unin"
      "stall",
  };

  std::set<std::string> userProgramKeys;
  expandRegistryGlobs(
      "HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
      userProgramKeys);
  programKeys.insert(userProgramKeys.begin(), userProgramKeys.end());

  std::set<std::string> processedPrograms;
  for (const auto& k : programKeys) {
    keyEnumPrograms(k, processedPrograms, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
