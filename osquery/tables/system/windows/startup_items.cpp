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
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows"
    "\\CurrentVersion\\Run%",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
    "\\Policies\\Explorer\\Run%",
    "HKEY_USERS\\%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%",
    "HKEY_USERS\\%\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows"
    "\\CurrentVersion\\Run%",
    "HKEY_USERS\\%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
    "\\Policies\\Explorer\\Run%",
};
const std::set<std::string> kStartupFolderDirectories = {
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%%",
    "C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start "
    "Menu\\Programs\\Startup\\%%"};
const std::set<std::string> kStartupStatusRegKeys = {
    "HKEY_LOCAL_"
    "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupAp"
    "proved\\%%",
    "HKEY_USERS\\%"
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
    "\\%%",
};

// Starts with 0[0-9] but not followed by all 0s
const auto kStartupDisabledRegex = boost::regex("^0[0-9](?!0+$).*$");

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // These are UNION instead of OR to workaround #3145
  std::string startupSubQuery =
      "SELECT name,data,key FROM (select name,data,key,type from registry "
      "WHERE key LIKE \"" +
      boost::join(kStartupRegKeys,
                  "\" UNION SELECT name,data,key,type FROM registry WHERE key "
                  "LIKE \"") +
      "\") WHERE NOT (type = \"subkey\" OR name = \"" + kDefaultRegName + "\")";
  std::string startupFolderSubQuery =
      "SELECT filename,path,directory FROM file WHERE path LIKE \"" +
      boost::join(kStartupFolderDirectories, "\" OR path LIKE \"") + "\"";
  std::string statusSubQuery =
      "SELECT name,data AS status FROM (select name,data from registry WHERE "
      "key LIKE \"" +
      boost::join(kStartupStatusRegKeys,
                  "\" UNION SELECT name,data FROM registry WHERE key LIKE \"") +
      "\")";

  SQL startupResults("SELECT key,R1.name as name,data,status FROM (" +
                     startupSubQuery + " UNION " + startupFolderSubQuery +
                     ") R1 LEFT JOIN (" + statusSubQuery +
                     ") R2 ON R1.name = R2.name ");

  for (const auto& startup : startupResults.rows()) {
    Row r;

    if (boost::starts_with(startup.at("key"), "HKEY_LOCAL_MACHINE") ||
        boost::starts_with(startup.at("key"), "C:\\ProgramData")) {
      r["username"] = "SYSTEM";
    } else if (boost::starts_with(startup.at("key"), "C:\\Users")) {
      auto dirs = osquery::split(startup.at("key"), "\\");
      if (dirs.size() > 2) {
        r["username"] = dirs[2];
      }
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
    r["source"] = startup.at("key");
    r["type"] = "Startup Item";
    results.push_back(r);
  }
  return results;
}
}
}
