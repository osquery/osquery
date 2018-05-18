/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/tables/system/windows/registry.h"

#define DECLARE_TABLE_IMPLEMENTATION_programs
#include <generated/tables/tbl_programs_defs.hpp>

namespace osquery {
namespace tables {

void keyEnumPrograms(const std::string& key,
                     std::set<std::string>& processed,
                     QueryData& results) {
  QueryData regResults;
  queryKey(key, regResults);
  for (const auto& rKey : regResults) {
    // Each subkey represents a program, skip if not a subkey
    if (rKey.at("type") != "subkey") {
      continue;
    }

    // Ensure we only process each program one time
    const auto& fullProgramName = rKey.at("path");
    if (processed.find(fullProgramName) != processed.end()) {
      continue;
    }
    processed.insert(fullProgramName);

    // Query additional information about the program
    QueryData appResults;
    queryKey(fullProgramName, appResults);
    Row r;

    // Attempt to derive the program identifying GUID
    std::string identifyingNumber;
    boost::smatch matches;
    boost::regex expression(
        "({[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+})"
        "$");
    if (boost::regex_search(fullProgramName, matches, expression)) {
      identifyingNumber = matches[0];
      r["identifying_number"] = identifyingNumber;
    }

    for (const auto& aKey : appResults) {
      auto name = aKey.find("name");
      if (identifyingNumber.empty() && name->second == "BundleIdentifier") {
        r["identifying_number"] = aKey.at("data");
      }
      if (name->second == "DisplayName") {
        r["name"] = aKey.at("data");
      }
      if (name->second == "DisplayVersion") {
        r["version"] = aKey.at("data");
      }
      if (name->second == "InstallLocation") {
        r["install_location"] = aKey.at("data");
      }
      if (name->second == "InstallSource") {
        r["install_source"] = aKey.at("data");
      }
      if (name->second == "Language") {
        r["language"] = aKey.at("data");
      }
      if (name->second == "Publisher") {
        r["publisher"] = aKey.at("data");
      }
      if (name->second == "UninstallString") {
        r["uninstall_string"] = aKey.at("data");
      }
      if (name->second == "InstallDate") {
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
