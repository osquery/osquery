/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/tables/system/windows/registry.h"
#include "osquery/tables/system/windows/users.h"
#include <osquery/utils/conversions/split.h>
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

std::string getUserShell(const std::string& sid) {
  // TODO: This column exists for cross-platform consistency, but
  // the answer on Windows is arbitrary. %COMSPEC% env variable may
  // be the best answer. Currently, hard-coded.
  return "C:\\Windows\\system32\\cmd.exe";
}

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

// If given a list of UIDs to constrain the results, check if a particular SID
// has a RID that matches any of those UIDs.
bool sidMatchesAnyDesiredUids(const std::set<std::string>& uidStrings,
                              const std::string& sidString) {
  // If there is no constraint of UIDs given, results will not be filtered
  if (uidStrings.empty()) {
    return true;
  }

  auto toks = osquery::split(sidString, "-");
  auto uid = toks.at(toks.size() - 1);
  for (auto desiredUid : uidStrings) {
    if (uid.compare(desiredUid) == 0) {
      return true;
    }
  }

  return false;
}

// Given a SID, retrieve information about the matching user
void genUser(const std::string& sidString, QueryData& results) {
  Row r;

  r["uuid"] = sidString;
  r["directory"] = getUserHomeDir(sidString);
  r["shell"] = getUserShell(sidString);
  r["type"] = kWellKnownSids.find(sidString) == kWellKnownSids.end()
                  ? "roaming"
                  : "special";

  PSID sid;
  auto ret = ConvertStringSidToSidA(sidString.c_str(), &sid);
  if (ret == 0) {
    VLOG(1) << "Converting SIDstring to SID failed with " << GetLastError();
    return;
  } else {
    auto uid = getUidFromSid(sid);
    auto gid = getGidFromSid(sid);
    r["uid"] = BIGINT(uid);
    r["gid"] = BIGINT(gid);
    r["uid_signed"] = INTEGER(uid);
    r["gid_signed"] = INTEGER(gid);

    wchar_t accntName[UNLEN] = {0};
    wchar_t domName[DNLEN] = {0};
    unsigned long accntNameLen = UNLEN;
    unsigned long domNameLen = DNLEN;
    SID_NAME_USE eUse;
    ret = LookupAccountSidW(
        nullptr, sid, accntName, &accntNameLen, domName, &domNameLen, &eUse);
    r["username"] = ret != 0 ? wstringToString(accntName) : "";

    // Also attempt to get the user account description comment. Move on if
    // NetUserGetInfo returns an error, as it will for some system accounts.
    unsigned long dwBasicUserInfoLevel = 2;
    LPBYTE userLvl2Buff = nullptr;
    ret =
        NetUserGetInfo(nullptr, accntName, dwBasicUserInfoLevel, &userLvl2Buff);
    if (ret == NERR_Success && userLvl2Buff != nullptr) {
      r["description"] =
          wstringToString(LPUSER_INFO_2(userLvl2Buff)->usri2_comment);
    }

    if (userLvl2Buff != nullptr) {
      NetApiBufferFree(userLvl2Buff);
    }

    results.push_back(r);
  }
}

// Enumerate the users from the profiles key in the Registry, matching only
// the UIDs/RIDs (if any) and skipping any SIDs of local-only users that
// were already processed in the earlier API-based enumeration.
void processRoamingProfiles(const std::set<std::string>& selectedUids,
                            const std::set<std::string>& processedSids,
                            QueryData& results) {
  QueryData regResults;
  queryKey(kRegProfilePath, regResults);

  for (const auto& profile : regResults) {
    Row r;
    if (profile.at("type") != "subkey") {
      continue;
    }

    auto sidString = profile.at("name");

    if (sidMatchesAnyDesiredUids(selectedUids, sidString)) {
      // Skip this user if already processed
      if (processedSids.find(sidString) == processedSids.end()) {
        genUser(sidString, results);
      }
    }
  }
}

// Enumerate all local users, constraining results to the list of UIDs if
// any, and recording all enumerated users' SIDs to exclude later from the
// walk of the Roaming Profiles key in the registry.
void processLocalAccounts(const std::set<std::string>& selectedUids,
                          std::set<std::string>& processedSids,
                          QueryData& results) {
  // Enumerate the users by only the usernames (level 0 struct) and then
  // get the desired level of info for each (level 4 struct includes SIDs).
  unsigned long dwUserInfoLevel = 0;
  unsigned long dwDetailedUserInfoLevel = 4;
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
      auto iterBuff = LPUSER_INFO_0(userBuffer);
      for (size_t i = 0; i < dwNumUsersRead; i++) {
        LPBYTE userLvl4Buff = nullptr;
        ret = NetUserGetInfo(nullptr,
                             iterBuff->usri0_name,
                             dwDetailedUserInfoLevel,
                             &userLvl4Buff);

        if (ret != NERR_Success || userLvl4Buff == nullptr) {
          if (userLvl4Buff != nullptr) {
            NetApiBufferFree(userLvl4Buff);
          }
          VLOG(1) << "Failed to get SID for "
                  << wstringToString(iterBuff->usri0_name)
                  << " with error code " << ret;
          iterBuff++;
          continue;
        }

        // Will return empty string on fail
        auto sid = LPUSER_INFO_4(userLvl4Buff)->usri4_user_sid;
        auto uid = getUidFromSid(sid);
        auto gid = LPUSER_INFO_4(userLvl4Buff)->usri4_primary_group_id;
        auto sidString = psidToString(sid);
        processedSids.insert(sidString);

        if (sidMatchesAnyDesiredUids(selectedUids, sidString)) {
          Row r;
          r["uuid"] = sidString;
          r["username"] = wstringToString(iterBuff->usri0_name);
          r["uid"] = BIGINT(uid);
          r["gid"] = BIGINT(gid);
          r["uid_signed"] = INTEGER(uid);
          r["gid_signed"] = INTEGER(gid);
          r["description"] =
              wstringToString(LPUSER_INFO_4(userLvl4Buff)->usri4_comment);
          r["directory"] = getUserHomeDir(sidString);
          r["shell"] = getUserShell(sidString);
          r["type"] = "local";

          results.push_back(r);
        }

        // Free the buffer allocated by NetUserGetInfo()
        if (userLvl4Buff != nullptr) {
          NetApiBufferFree(userLvl4Buff);
        }
        iterBuff++; // index to the next record returned by NetUserEnum()
      }
    } else {
      // If there are no local users something may be amiss.
      LOG(WARNING) << "NetUserEnum failed with " << ret;
    }

    // Free the buffer allocated by NetUserEnum()
    if (userBuffer != nullptr) {
      NetApiBufferFree(userBuffer);
    }

  } while (ret == ERROR_MORE_DATA);
}

QueryData genUsers(QueryContext& context) {
  QueryData results;
  std::set<std::string> processedSids;
  std::set<std::string> selectedUids;

  // implement index on UUID (SID on Windows) column by returning only the
  // users in the constraint, bypassing the enumeration step entirely:
  if (context.constraints["uuid"].exists(EQUALS)) {
    auto sidStrings = context.constraints["uuid"].getAll(EQUALS);
    for (const auto& sidString : sidStrings) {
      genUser(sidString, results);
    }
  } else {
    // implement index on UID (RID on Windows) column by enumerating all users'
    // SIDS and finding matches with the UID portion, then returning matches:
    if (context.constraints["uid"].exists(EQUALS)) {
      selectedUids = context.constraints["uid"].getAll(EQUALS);
    }
    processLocalAccounts(selectedUids, processedSids, results);
    processRoamingProfiles(selectedUids, processedSids, results);
  }

  return results;
}
}
}
