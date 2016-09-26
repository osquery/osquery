/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma comment(lib, "netapi32.lib")

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on
#include <Shlobj.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genUsers(QueryContext& context) {
  QueryData results;

  // USER_INFO_3 conains generic user information
  LPUSER_INFO_3 pUserBuffer = nullptr;
  DWORD dwGenericUserLevel = 3;
  DWORD dwPreferredMaxLength = MAX_PREFERRED_LENGTH;
  DWORD dwEntriesRead = 0;
  DWORD dwTotalEntries = 0;
  DWORD dwResumeHandle = 0;
  NET_API_STATUS nEnumStatus;

  nEnumStatus = NetUserEnum(nullptr,
                            dwGenericUserLevel,
                            FILTER_NORMAL_ACCOUNT,
                            (LPBYTE*)&pUserBuffer,
                            dwPreferredMaxLength,
                            &dwEntriesRead,
                            &dwTotalEntries,
                            &dwResumeHandle);

  // We save the original pointer to the USER_INFO_3 buff for mem management
  LPUSER_INFO_3 pUserIterationBuffer = pUserBuffer;
  if (pUserIterationBuffer == nullptr || nEnumStatus != NERR_Success) {
    if (pUserBuffer != nullptr) {
      NetApiBufferFree(pUserBuffer);
    }
    return results;
  }

  for (DWORD i = 0; i < dwEntriesRead; i++) {
    Row r;
    r["username"] = wstringToString(pUserIterationBuffer->usri3_name);
    r["description"] = wstringToString(pUserIterationBuffer->usri3_comment);
    r["uid"] = BIGINT(pUserIterationBuffer->usri3_user_id);
    r["gid"] = BIGINT(pUserIterationBuffer->usri3_primary_group_id);
    r["uid_signed"] = r["uid"];
    r["gid_signed"] = r["gid"];
    r["shell"] = "C:\\Windows\\system32\\cmd.exe";

    // USER_INFO_23 contains detailed info, like the user Sid
    DWORD dwDetailedUserLevel = 23;
    LPUSER_INFO_23 pSidUserBuffer = nullptr;
    NET_API_STATUS nStatus;
    nStatus = NetUserGetInfo(nullptr,
                             pUserIterationBuffer->usri3_name,
                             dwDetailedUserLevel,
                             (LPBYTE*)&pSidUserBuffer);
    if (nStatus != NERR_Success) {
      if (pSidUserBuffer != nullptr) {
        NetApiBufferFree(pSidUserBuffer);
        pSidUserBuffer = nullptr;
      }
      continue;
    }

    LPTSTR sStringSid = nullptr;
    auto ret =
        ConvertSidToStringSid(pSidUserBuffer->usri23_user_sid, &sStringSid);
    if (ret == 0) {
      if (pSidUserBuffer != nullptr) {
        NetApiBufferFree(pSidUserBuffer);
      }
      continue;
    }
    r["uuid"] = sStringSid;
    std::string query = "SELECT LocalPath FROM Win32_UserProfile where SID=\"" +
                        std::string(sStringSid) + "\"";
    WmiRequest wmiRequest(query);
    std::vector<WmiResultItem>& wmiResults = wmiRequest.results();
    if (wmiResults.size() != 0) {
      wmiResults[0].GetString("LocalPath", r["directory"]);
    }
    LocalFree(sStringSid);
    NetApiBufferFree(pSidUserBuffer);

    results.push_back(r);
    pUserIterationBuffer++;
  }
  NetApiBufferFree(pUserBuffer);

  if (nEnumStatus == ERROR_MORE_DATA) {
    LOG(WARNING)
        << "NetUserEnum contains more data: users table may be incomplete";
  }

  return results;
}
}
}
