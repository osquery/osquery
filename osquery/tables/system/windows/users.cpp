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
namespace tables {

QueryData genUsers(QueryContext& context) {
  QueryData results;

  WmiRequest req("select * from Win32_UserProfile");
  if (!req.getStatus().ok()) {
    return results;
  }

  auto& wmiResults = req.results();
  for (const auto& res : wmiResults) {
    Row r;

    std::string sidString;
    res.GetString("LocalPath", r["directory"]);
    res.GetString("SID", sidString);
    r["uuid"] = sidString;

    PSID sid;
    auto ret = ConvertStringSidToSidA(sidString.c_str(), &sid);
    if (ret == 0) {
      TLOG << "Convert SID to string failed with: " << GetLastError();
    }

    wchar_t accntName[UNLEN] = {0};
    wchar_t domName[DNLEN] = {0};
    unsigned long accntNameLen = UNLEN;
    unsigned long domNameLen = DNLEN;
    SID_NAME_USE eUse;

    /// MSDN guaruntees the string values returned is null terminated.
    ret = LookupAccountSidW(
        nullptr, sid, accntName, &accntNameLen, domName, &domNameLen, &eUse);
    if (ret != 0) {
      r["username"] = wstringToString(accntName);
    } else {
      TLOG << "Lookup Account by SID failed with: " << GetLastError();
    }

    /// USER_INFO_3 contains detailed info, like the uid
    unsigned long dwDetailedUserLevel = 3;
    LPUSER_INFO_3 pUserInfoBuffer = nullptr;

    NET_API_STATUS nStatus;
    nStatus = NetUserGetInfo(nullptr,
                             accntName,
                             dwDetailedUserLevel,
                             reinterpret_cast<LPBYTE*>(&pUserInfoBuffer));

    if (nStatus == NERR_Success) {
      r["uid"] = INTEGER(pUserInfoBuffer->usri3_user_id);
      r["uid_signed"] = INTEGER(pUserInfoBuffer->usri3_user_id);
      r["gid"] = INTEGER(pUserInfoBuffer->usri3_primary_group_id);
      r["gid_signed"] = INTEGER(pUserInfoBuffer->usri3_primary_group_id);
      r["description"] =
          SQL_TEXT(wstringToString(pUserInfoBuffer->usri3_comment));
    } else {
      /// If NetUserGetInfo fails parse the uid manually
      auto sidTokens = osquery::split(sidString, "-");
      if (sidTokens.size() == 8) {
        r["uid"] = INTEGER(sidTokens.back());
        r["uid_signed"] = INTEGER(sidTokens.back());
      }
    }

    /// Note: there may be a way to get the users prefered shell
    r["shell"] = "C:\\Windows\\system32\\cmd.exe";
    results.push_back(r);

    if (pUserInfoBuffer != nullptr) {
      NetApiBufferFree(pUserInfoBuffer);
      pUserInfoBuffer = nullptr;
    }
  }
  return results;
}
}
}
