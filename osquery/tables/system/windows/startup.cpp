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

namespace osquery {
namespace tables {

QueryData genStartup(QueryContext& context) {
  QueryData results;
  std::string username;
  QueryData regResults;

  queryKey("HKEY_LOCAL_MACHINE" + kStartupPath, regResults);
  for (const auto& regResult : regResults) {
    if (regResult.find("data") != regResult.end()) {
      Row r;
      r["username"] = "system";
      r["path"] = regResult.at("data");
      r["name"] = regResult.at("name");
      results.push_back(r);
    }
  }

  regResults = QueryData();
  queryKey("HKEY_USERS", regResults);
  for (const auto& user : regResults) {
    if (user.at("type") != "subkey") {
      continue;
    }
    PSID sid;
    std::string username;
    auto ret = ConvertStringSidToSidA(user.at("name").c_str(), &sid);
    if (ret == 0) {
      LOG(INFO) << "Error converting string to SID: " + GetLastError();
      username = "";
    } else {
      wchar_t accntName[UNLEN] = {0};
      wchar_t domName[DNLEN] = {0};
      unsigned long accntNameLen = UNLEN;
      unsigned long domNameLen = DNLEN;
      SID_NAME_USE eUse;
      ret = LookupAccountSidW(
          nullptr, sid, accntName, &accntNameLen, domName, &domNameLen, &eUse);
      username = ret != 0 ? wstringToString(accntName) : "unknown";
    }
    QueryData res;
    queryKey(user.at("path") + kStartupPath, res);
    for (const auto& regResult : res) {
      if (regResult.find("data") != regResult.end()) {
        Row r;
        r["username"] = username;
        r["path"] = regResult.at("data");
        r["name"] = regResult.at("name");
        results.push_back(r);
      }
    }
  }
  return results;
}
}
}
