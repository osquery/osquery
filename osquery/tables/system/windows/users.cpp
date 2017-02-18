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
#include <osquery/tables.h>
#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/core/conversions.h"

namespace osquery {

std::string psidToString(PSID sid);
int getUidFromSid(PSID sid);
int getGidFromSid(PSID sid);

namespace tables {

void ProcessWinProfile(const WmiResultItem& wmiResult,
                       std::set<std::string>& processedSids,
                       QueryData& results) {
  Row r;
  std::string sidString;
  wmiResult.GetString("SID", sidString);

  r["uuid"] = sidString;
  processedSids.insert(sidString);
  wmiResult.GetString("LocalPath", r["directory"]);

  PSID sid;
  auto ret = ConvertStringSidToSidA(sidString.c_str(), &sid);
  if (ret == 0) {
    VLOG(1) << "Convert SID to string failed with " << GetLastError();
  }
  r["uid"] = INTEGER(getUidFromSid(sid));
  r["gid"] = INTEGER(getGidFromSid(sid));
  r["uid_signed"] = r["uid"];
  r["gid_signed"] = r["gid"];
  r["shell"] = "C:\\Windows\\system32\\cmd.exe";

  WmiRequest accntReq(
      "select Description, Name from Win32_UserAccount where sid = \"" +
      r["uuid"] + "\"");
  auto& accntResults = accntReq.results();
  if (accntReq.getStatus().ok() && !accntResults.empty()) {
    accntResults[0].GetString("Description", r["description"]);
    accntResults[0].GetString("Name", r["username"]);
  } else {
    r["description"] = "";
    // If there is no entry in Win32_UserAccount this is a domain user
    wchar_t accntName[UNLEN] = {0};
    wchar_t domName[DNLEN] = {0};
    unsigned long accntNameLen = UNLEN;
    unsigned long domNameLen = DNLEN;
    SID_NAME_USE eUse;
    ret = LookupAccountSidW(
        nullptr, sid, accntName, &accntNameLen, domName, &domNameLen, &eUse);
    r["username"] = ret != 0 ? wstringToString(accntName) : "";
  }
  results.push_back(r);
}

void processWinLocalAccounts(const std::set<std::string>& processedSids,
                             QueryData& results) {
  unsigned long dwUserInfoLevel = 3;
  unsigned long dwNumUsersRead = 0;
  unsigned long dwTotalUsers = 0;
  unsigned long resumeHandle = 0;
  unsigned long ret = 0;
  LPBYTE userBuffer = nullptr;
  do {
    ret = NetUserEnum(nullptr,
                      dwUserInfoLevel,
                      0,
                      &userBuffer,
                      MAX_PREFERRED_LENGTH,
                      &dwNumUsersRead,
                      &dwTotalUsers,
                      &resumeHandle);

    if ((ret == NERR_Success || ret == ERROR_MORE_DATA) &&
        userBuffer != nullptr) {
      auto iterBuff = LPUSER_INFO_3(userBuffer);
      for (size_t i = 0; i < dwNumUsersRead; i++) {
        // User level 4 contains the SID value
        unsigned long dwDetailedUserInfoLevel = 4;
        LPBYTE userLvl4Buff = nullptr;
        ret = NetUserGetInfo(nullptr,
                             iterBuff->usri3_name,
                             dwDetailedUserInfoLevel,
                             &userLvl4Buff);

        if (ret != NERR_Success || userLvl4Buff == nullptr) {
          if (userLvl4Buff != nullptr) {
            NetApiBufferFree(userLvl4Buff);
          }
          VLOG(1) << "Failed to get sid for "
                  << wstringToString(iterBuff->usri3_name)
                  << " with error code " << ret;
          iterBuff++;
          continue;
        }

        // Will return empty string on fail
        auto sid = LPUSER_INFO_4(userLvl4Buff)->usri4_user_sid;
        auto sidString = psidToString(sid);
        if (processedSids.find(sidString) != processedSids.end()) {
          if (userLvl4Buff != nullptr) {
            NetApiBufferFree(userLvl4Buff);
          }

          iterBuff++;
          continue;
        }

        Row r;
        r["uuid"] = psidToString(sid);
        r["username"] = wstringToString(iterBuff->usri3_name);
        r["uid"] = INTEGER(iterBuff->usri3_user_id);
        r["gid"] = INTEGER(iterBuff->usri3_primary_group_id);
        r["uid_signed"] = r["uid"];
        r["gid_signed"] = r["gid"];
        r["description"] =
            wstringToString(LPUSER_INFO_4(userLvl4Buff)->usri4_comment);
        r["directory"] =
            wstringToString(LPUSER_INFO_4(userLvl4Buff)->usri4_home_dir);
        r["shell"] = "C:\\Windows\\System32\\cmd.exe";
        if (userLvl4Buff != nullptr) {
          NetApiBufferFree(userLvl4Buff);
        }

        results.push_back(r);
        iterBuff++;
      }
    } else {
      // If there are no local users something may be amiss.
      LOG(WARNING) << "NetUserEnum failed with " << ret;
    }
    if (userBuffer != nullptr) {
      NetApiBufferFree(userBuffer);
    }

  } while (ret == ERROR_MORE_DATA);
}

QueryData genUsers(QueryContext& context) {
  QueryData results;

  // Enumerate all accounts with a profile on this computer
  WmiRequest req("select * from Win32_UserProfile");
  if (!req.getStatus().ok()) {
    return results;
  }
  auto& wmiResults = req.results();
  std::set<std::string> processedSids;

  for (const auto& res : wmiResults) {
    ProcessWinProfile(res, processedSids, results);
  }

  // Lastly do a sweep for any accounts that don't yet have a profile
  processWinLocalAccounts(processedSids, results);
  return results;
}
}
}
