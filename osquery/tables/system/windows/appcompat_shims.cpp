/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

#include <osquery/utils/conversions/split.h>

#include <osquery/tables/system/windows/registry.h>

namespace osquery {
namespace tables {

struct sdb {
  std::string description;
  unsigned long long installTimestamp;
  std::string path;
  std::string type;
};

QueryData genShims(QueryContext& context) {
  QueryData results;
  QueryData sdbResults;
  QueryData shimResults;
  std::map<std::string, sdb> sdbs;

  queryKey(
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows "
      "NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
      sdbResults);
  for (const auto& rKey : sdbResults) {
    if (rKey.count("type") == 0 || rKey.count("path") == 0) {
      continue;
    }
    QueryData regResults;
    sdb sdb;
    std::string subkey = rKey.at("path");
    auto start = subkey.find('{');
    if (start == std::string::npos) {
      continue;
    }
    if (start > subkey.size()) {
      continue;
    }
    std::string sdbId = subkey.substr(start, subkey.length());
    // make sure it's a sane uninstall key
    queryKey(subkey, regResults);
    for (const auto& aKey : regResults) {
      if (aKey.count("name") == 0 || aKey.count("data") == 0) {
        continue;
      }
      if (aKey.at("name") == "DatabaseDescription") {
        sdb.description = aKey.at("data");
      }
      if (aKey.at("name") == "DatabaseInstallTimeStamp") {
        // take this crazy windows timestamp to a unix timestamp
        sdb.installTimestamp = std::stoull(aKey.at("data"));
        sdb.installTimestamp = (sdb.installTimestamp / 10000000) - 11644473600;
      }
      if (aKey.at("name") == "DatabasePath") {
        sdb.path = aKey.at("data");
      }
      if (aKey.at("name") == "DatabaseType") {
        sdb.type = aKey.at("data");
      }
    }
    sdbs[sdbId] = sdb;
  }

  queryKey(
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
      "CurrentVersion\\AppCompatFlags\\Custom",
      shimResults);
  for (const auto& rKey : shimResults) {
    if (rKey.count("type") == 0 || rKey.count("path") == 0 ||
        rKey.at("type") != "subkey") {
      continue;
    }

    QueryData regResults;
    std::string subkey = rKey.at("path");
    auto toks = split(rKey.at("path"), "\\");
    auto executable = toks[toks.size() - 1];
    queryKey(subkey, regResults);
    for (const auto& aKey : regResults) {
      Row r;
      std::string sdbId;
      if (aKey.at("name").length() > 4) {
        sdbId = aKey.at("name").substr(0, aKey.at("name").length() - 4);
      }
      if (sdbs.count(sdbId) == 0) {
        continue;
      }
      r["executable"] = executable;
      r["path"] = sdbs.at(sdbId).path;
      r["description"] = sdbs.at(sdbId).description;
      r["install_time"] = INTEGER(sdbs.at(sdbId).installTimestamp);
      r["type"] = sdbs.at(sdbId).type;
      r["sdb_id"] = sdbId;
      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
