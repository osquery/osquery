/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

const std::set<std::string> kStartupRegKeys = {
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%",
    "HKEY_USERS\\%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%",
};
const std::set<std::string> kStartupFolderDirectories = {
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start "
    "Menu\\Programs\\Startup"};
const std::set<std::string> kStartupStatusRegKeys = {
    "HKEY_LOCAL_"
    "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupAp"
    "proved\\%%",
    "HKEY_USERS\\%"
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
    "\\%%",
};
const auto kStartupEnabledRegex = boost::regex("0[0-9]0+");

static inline QueryData buildRegistryQuery(const std::set<std::string>& keys) {
  QueryData results;
  for (const auto& key : keys) {
    SQL res("SELECT * FROM registry WHERE key LIKE \"" + key +
            "\" AND NOT type = \"subkey\" AND NOT name = \"" + kDefaultRegName +
            "\"");
    results.insert(results.end(), res.rows().begin(), res.rows().end());
  }
  return results;
}

QueryData genStartup(QueryContext& context) {
  QueryData results;
  std::vector<std::string> keys;

  auto regResults = buildRegistryQuery(kStartupRegKeys);
  auto statusResults = buildRegistryQuery(kStartupStatusRegKeys);

  for (const auto& regResult : regResults) {
    Row r;

    if (boost::starts_with(regResult.at("key"), "HKEY_LOCAL_MACHINE")) {
      r["username"] = "SYSTEM";
    } else {
      std::string username;
      if (getUsernameFromKey(regResult.at("key"), username).ok()) {
        r["username"] = std::move(username);
      } else {
        LOG(INFO) << "Failed to get username from sid";
      }
    }

    SQL status("SELECT * from registry where (key LIKE \"" +
               boost::join(kStartupStatusRegKeys, "\" OR key LIKE \"") +
               "\") and name = \"" + regResult.at("name") + "\"");
    if (status.rows().size() > 0) {
      if (regex_match(status.rows()[0].at("data"), kStartupEnabledRegex)) {
        r["status"] = "enabled";
      } else {
        r["status"] = "disabled";
      }
    }

    r["name"] = regResult.at("name");
    r["path"] = regResult.at("data");
    r["startup_path"] = regResult.at("key");
    results.push_back(r);
  }
  return results;
}
}
}
