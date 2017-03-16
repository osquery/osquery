/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/tables/system/windows/registry.h"

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

  queryKey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows "
           "NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
           sdbResults);
  for (const auto& rKey : sdbResults) {
    if (rKey.at("type") != "subkey") {
      continue;
    }
    QueryData regResults;
    sdb sdb;
    std::string subkey = rKey.at("path");
    auto start = subkey.find("{");
    if (start == std::string::npos) {
      continue;
    }
    std::string sdbId = subkey.substr(start, subkey.length());
    // make sure it's a sane uninstall key
    queryKey(subkey, regResults);
    for (const auto& aKey : regResults) {
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
    QueryData regResults;
    if (rKey.at("type") == "subkey") {
      std::string subkey = rKey.at("path");
      auto start = rKey.at("path").rfind("\\");
      if (start == std::string::npos) {
        continue;
      }
      std::string executable =
        rKey.at("path").substr(start + 1, rKey.at("subkey").length());
      // make sure it's a sane uninstall key
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
  }

  return results;
}
}
}
