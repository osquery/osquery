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

// Anything that isn't 0[0-9] followed by all 0s. e.g. 0300000016151d0d1faed201
const auto kStartupDisabledRegex = boost::regex("^0[0-9](?!0+$).*$");

QueryData genStartup(QueryContext& context) {
  QueryData results;

  std::string startupSubQuery =
      "SELECT name,data,key FROM registry WHERE (key LIKE \"" +
      boost::join(kStartupRegKeys, "\" OR key LIKE \"") +
      "\") AND NOT (type = \"subkey\" OR name = \"" + kDefaultRegName + "\")";
  std::string statusSubQuery =
      "SELECT name,data AS status FROM registry WHERE key LIKE \"" +
      boost::join(kStartupStatusRegKeys, "\" OR key LIKE \"") + "\"";
  SQL startupResults("SELECT key,R1.name as name,data,status FROM (" +
                     startupSubQuery + ") R1 LEFT JOIN (" + statusSubQuery +
                     ") R2 ON R1.name = R2.name ");

  for (const auto& startup : startupResults.rows()) {
    Row r;

    if (boost::starts_with(startup.at("key"), "HKEY_LOCAL_MACHINE")) {
      r["username"] = "SYSTEM";
    } else {
      std::string username;
      if (getUsernameFromKey(startup.at("key"), username).ok()) {
        r["username"] = std::move(username);
      } else {
        LOG(INFO) << "Failed to get username from sid";
      }
    }

    r["status"] = regex_match(startup.at("status"), kStartupDisabledRegex)
                      ? "disabled"
                      : "enabled";
    r["name"] = startup.at("name");
    r["path"] = startup.at("data");
    r["startup_path"] = startup.at("key");
    results.push_back(r);
  }
  return results;
}
}
}
