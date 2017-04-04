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

const std::vector<std::string> kStartupRegKeys = {
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_USERS\\%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
};
const std::vector<std::string> kStartupFolderDirectories = {
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start "
    "Menu\\Programs\\Startup"};
const std::string kStartupStatusRegKeys =
    "HKEY_USERS\\%"
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
    "\\%%";
const auto kStartupEnabledRegex = boost::regex("0[0-9]0+");
const std::string kDefaultRegExcludeSQL =
    "NOT type = \"subkey\" AND NOT name = \"" + kDefaultRegName + "\"";

QueryData genStartup(QueryContext& context) {
  QueryData results;
  std::string username;
  std::vector<std::string> keys;

  SQL regResults("SELECT * FROM registry WHERE (key LIKE \"" +
                 osquery::join(kStartupRegKeys, "\" OR key LIKE \"") +
                 "\") AND " + kDefaultRegExcludeSQL);
  SQL statusResults("SELECT name, data FROM registry WHERE key LIKE \"" +
                    kStartupStatusRegKeys + "\" AND " + kDefaultRegExcludeSQL);

  std::for_each(
      regResults.rows().begin(),
      regResults.rows().end(),
      [&](const auto& regResult) {
        Row r;
        std::string username;
        if (boost::starts_with(regResult.at("key"), "HKEY_LOCAL_MACHINE")) {
          username = "local_machine";
        } else {
          if (!getUsernameFromKey(regResult.at("key"), username).ok()) {
            LOG(INFO) << "Failed to get username from sid";
            username = "unknown";
          }
        }
        r["username"] = username;
        r["name"] = regResult.at("name");
        r["path"] = regResult.at("data");
        r["registry_key"] = regResult.at("key");
        r["status"] = "unknown";
        for (const auto& status : statusResults.rows()) {
          if (status.at("name") == regResult.at("name")) {
            if (regex_match(status.at("data"), kStartupEnabledRegex)) {
              r["status"] = "enabled";
            } else {
              r["status"] = "disabled";
            }
          }
        }
        results.push_back(r);
      });
  return results;
}
}
}
