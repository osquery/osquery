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
// clang-format off
#include <LM.h>
// clang-format on

#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"

const std::string kStartupPath =
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
const std::set<std::string> kStartupConfigPaths = {
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
    "\\Run",
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
    "\\Run32",
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
    "\\StartupFolder",
};
const auto kStartupEnabledRegex = boost::regex("0[0-9]0+");

namespace osquery {
namespace tables {

static inline std::string getStartupStatus(const std::string& startupName) {
  QueryData regResults;
  std::string status = "";
  QueryData userKeys;
  std::vector<std::string> keys;

  queryKey("HKEY_USERS", regResults);
  for (const auto& path : kStartupConfigPaths) {
    for (const auto& regResult : regResults) {
      keys.push_back(regResult.at("path") + path);
    }
    keys.push_back("HKEY_LOCAL_MACHINE" + path);
  }
  for (const auto& key : keys) {
    queryKey(key, regResults);
    for (const auto& regResult : regResults) {
      if (regResult.at("name") == startupName) {
        if (regex_match(regResult.at("data"), kStartupEnabledRegex)) {
          status = "enabled";
          break;
        } else {
          status = "disabled";
          break;
        }
      }
    }
  }
  return status;
}

QueryData genStartup(QueryContext& context) {
  QueryData results;
  std::string username;
  QueryData regResults;
  std::vector<std::string> keys;

  queryKey("HKEY_USERS", regResults);
  for (const auto& regResult : regResults) {
    keys.push_back(regResult.at("path") + kStartupPath);
  }
  keys.push_back("HKEY_LOCAL_MACHINE" + kStartupPath);
  for (const auto& key : keys) {
    queryKey(key, regResults);
    for (const auto& regResult : regResults) {
      if (regResult.at("type") == "subkey" ||
          regResult.at("name") == "(Default)") {
        continue;
      }
      if (boost::starts_with(key, "HKEY_USERS")) {
        PSID sid;
        std::string username;
        if (!ConvertStringSidToSidA(
                osquery::split(regResult.at("key"), kRegSep)[1].c_str(),
                &sid)) {
          username = "unknown";
        } else {
          wchar_t accntName[UNLEN] = {0};
          wchar_t domName[DNLEN] = {0};
          unsigned long accntNameLen = UNLEN;
          unsigned long domNameLen = DNLEN;
          SID_NAME_USE eUse;
          auto ret = LookupAccountSidW(nullptr,
                                       sid,
                                       accntName,
                                       &accntNameLen,
                                       domName,
                                       &domNameLen,
                                       &eUse);
          username = ret != 0 ? wstringToString(accntName) : "unknown";
        }
      } else {
        username = "system";
      }
      Row r;
      r["username"] = "system";
      r["path"] = regResult.at("data");
      r["name"] = regResult.at("name");
      r["registry_key"] = regResult.at("key");
      r["status"] = getStartupStatus(regResult.at("name"));
      results.push_back(r);
    }
  }
  return results;
}
}
}
