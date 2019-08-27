/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/system.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>

#include "osquery/tables/system/windows/registry.h"
#include "osquery/tables/system/windows/users.h"
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/process/process.h>

namespace osquery {

std::string psidToString(PSID sid);
uint32_t getUidFromSid(PSID sid);
uint32_t getGidFromSid(PSID sid);

const std::string kRegProfilePath =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows "
    "NT\\CurrentVersion\\ProfileList";
const char kRegSep = '\\';
const std::set<std::string> kWellKnownSids = {
    "S-1-5-1",
    "S-1-5-2",
    "S-1-5-3",
    "S-1-5-4",
    "S-1-5-6",
    "S-1-5-7",
    "S-1-5-8",
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-12",
    "S-1-5-13",
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-21",
    "S-1-5-32",
};

namespace tables {

std::string getUserHomeDir(const std::string& sid) {
  QueryData res;
  queryKey(kRegProfilePath + kRegSep + sid, res);
  for (const auto& kKey : res) {
    if (kKey.at("name") == "ProfileImagePath") {
      return kKey.at("data");
    }
  }
  return "";
}

void processRoamingProfiles(const std::set<std::string>& processedSids,
                            QueryData& results) {
  QueryData regResults;
  queryKey(kRegProfilePath, regResults);

  for (const auto& profile : regResults) {
    Row r;
    if (profile.at("type") != "subkey") {
      continue;
    }

    auto sidString = profile.at("name");
    if (processedSids.find(sidString) != processedSids.end()) {
      continue;
    }
    r["uuid"] = sidString;
    r["directory"] = getUserHomeDir(sidString);

    PSID sid;
    auto ret = ConvertStringSidToSidA(sidString.c_str(), &sid);
    if (ret == 0) {
      VLOG(1) << "Convert SID to string failed with " << GetLastError();
    }
    auto uid = getUidFromSid(sid);
    auto gid = getGidFromSid(sid);
    r["uid"] = BIGINT(uid);
    r["gid"] = BIGINT(gid);
    r["uid_signed"] = INTEGER(uid);
    r["gid_signed"] = INTEGER(gid);
    r["type"] = kWellKnownSids.find(sidString) == kWellKnownSids.end()
                    ? "roaming"
                    : "special";

    // TODO
    r["shell"] = "C:\\Windows\\system32\\cmd.exe";
    r["description"] = "";

    wchar_t accntName[UNLEN] = {0};
    wchar_t domName[DNLEN] = {0};
    unsigned long accntNameLen = UNLEN;
    unsigned long domNameLen = DNLEN;
    SID_NAME_USE eUse;
    ret = LookupAccountSidW(
        nullptr, sid, accntName, &accntNameLen, domName, &domNameLen, &eUse);
    r["username"] = ret != 0 ? wstringToString(accntName) : "";
    results.push_back(r);
  }
}

void processLocalAccounts(std::set<std::string>& processedSids,
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
        processedSids.insert(sidString);

        Row r;
        r["uuid"] = psidToString(sid);
        r["username"] = wstringToString(iterBuff->usri3_name);
        auto uid = iterBuff->usri3_user_id;
        auto gid = iterBuff->usri3_primary_group_id;
        r["uid"] = BIGINT(uid);
        r["gid"] = BIGINT(gid);
        r["uid_signed"] = INTEGER(uid);
        r["gid_signed"] = INTEGER(gid);
        r["description"] =
            wstringToString(LPUSER_INFO_4(userLvl4Buff)->usri4_comment);
        r["directory"] = getUserHomeDir(sidString);
        r["shell"] = "C:\\Windows\\System32\\cmd.exe";
        r["type"] = "local";
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
  std::set<std::string> processedSids;

  processLocalAccounts(processedSids, results);
  processRoamingProfiles(processedSids, results);

  return results;
}
}
}
