/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

const std::string kADConfigPath =
    "/Library/Preferences/OpenDirectory/"
    "Configurations/Active Directory/";

void genADConfig(const std::string& path, QueryData& results) {
  auto config = SQL::selectAllFrom("plist", "path", EQUALS, path);
  if (config.size() == 0 || config[0].count("key") == 0) {
    // Fail if the file could not be plist-parsed.
    return;
  }

  // Walk through module options quickly to find the trust domain.
  // The file name and domain will be included in every row.
  auto name = config[0].at("key");
  std::string domain;
  for (const auto& row : config) {
    if (row.count("subkey") > 0 &&
        row.at("subkey") == "ActiveDirectory/trust domain") {
      domain = row.count("value") > 0 ? row.at("value") : "";
      break;
    }
  }

  // Iterate again with the domain known, searching for options.
  for (const auto& row : config) {
    Row r;
    r["domain"] = domain;
    r["name"] = name;

    // Get references to common columns.
    if (row.count("key") == 0 || row.count("subkey") == 0) {
      continue;
    }
    const auto& key = row.at("key");
    const auto& subkey = row.at("subkey");
    if (key == "trustoptions" ||
        key == "trustkerberosprincipal" ||
        key == "trustaccount" ||
        key == "trusttype") {
      r["option"] = key;
      r["value"] = row.count("value") > 0 ? row.at("value") : "";
      results.push_back(r);
    } else if (key == "options") {
      // The options key has a single subkey with the option name.
      r["option"] = subkey;
      r["value"] = row.count("value") > 0 ? row.at("value") : "";
      results.push_back(r);
    } else if (key == "module options") {
      // Module options may contain 'managed client template', skip those.
      if (subkey.find("managed client template") != std::string::npos) {
        continue;
      }

      // Skip the "ActiveDirectory/" preamble.
      r["option"] = subkey.substr(16);
      r["value"] = row.count("value") > 0 ? row.at("value") : "";
      results.push_back(r);
    }
  }
}

QueryData genADConfig(QueryContext& context) {
  QueryData results;

  // Not common to have multiple domains configured, but iterate over any file
  // within the known-path for AD plists.
  std::vector<std::string> configs;
  if (listFilesInDirectory(kADConfigPath, configs).ok()) {
    for (const auto& path : configs) {
      genADConfig(path, results);
    }
  }

  return results;
}
}
}
