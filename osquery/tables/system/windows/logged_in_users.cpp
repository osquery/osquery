/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wtsapi32.h>
#include <winsock2.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/filesystem/fileops.h"

const std::map<int, std::string> kSessionStates = {
    {WTSActive, "active"},
    {WTSDisconnected, "disconnected"},
    {WTSConnected, "connected"},
    {WTSConnectQuery, "connectquery"},
    {WTSShadow, "shadow"},
    {WTSIdle, "idle"},
    {WTSListen, "listen"},
    {WTSReset, "reset"},
    {WTSDown, "down"},
    {WTSInit, "init"}};

namespace osquery {
namespace tables {

QueryData genLoggedInUsers(QueryContext& context) {
  QueryData results;

  PWTS_SESSION_INFO_1 pSessionInfo;
  unsigned long count;
  /*
   * As per the MSDN:
   * This parameter is reserved. Always set this parameter to one.
   */
  unsigned long level = 1;
  auto res = WTSEnumerateSessionsEx(
      WTS_CURRENT_SERVER_HANDLE, &level, 0, &pSessionInfo, &count);

  if (res == 0) {
    return results;
  }

  for (size_t i = 0; i < count; i++) {
    Row r;

    char* sessionInfo = nullptr;
    unsigned long bytesRet = 0;
    res = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                                     pSessionInfo[i].SessionId,
                                     WTSSessionInfo,
                                     &sessionInfo,
                                     &bytesRet);
    if (res == 0 || sessionInfo == nullptr) {
      VLOG(1) << "Error querying WTS session information (" << GetLastError()
              << ")";
      continue;
    }
    auto wtsSession = (PWTSINFO)sessionInfo;
    r["user"] = SQL_TEXT(wtsSession->UserName);
    r["type"] = SQL_TEXT(kSessionStates.at(pSessionInfo[i].State));
    r["tty"] = pSessionInfo[i].pSessionName == nullptr
                   ? ""
                   : pSessionInfo[i].pSessionName;

    FILETIME utcTime = {0};
    unsigned long long unixTime = 0;
    utcTime.dwLowDateTime = wtsSession->ConnectTime.LowPart;
    utcTime.dwHighDateTime = wtsSession->ConnectTime.HighPart;
    if (utcTime.dwLowDateTime != 0 || utcTime.dwHighDateTime != 0) {
      unixTime = filetimeToUnixtime(utcTime);
    }
    r["time"] = INTEGER(unixTime);

    char* clientInfo = nullptr;
    bytesRet = 0;
    res = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                                     pSessionInfo[i].SessionId,
                                     WTSClientInfo,
                                     &clientInfo,
                                     &bytesRet);
    if (res == 0 || clientInfo == nullptr) {
      VLOG(1) << "Error querying WTS session information (" << GetLastError()
              << ")";
      results.push_back(r);
      continue;
    }
    auto wtsClient = (PWTSCLIENT)clientInfo;
    if (wtsClient->ClientAddressFamily == AF_INET) {
      r["host"] = std::to_string(wtsClient->ClientAddress[0]) + "." +
                  std::to_string(wtsClient->ClientAddress[1]) + "." +
                  std::to_string(wtsClient->ClientAddress[2]) + "." +
                  std::to_string(wtsClient->ClientAddress[3]);
    } else if (wtsClient->ClientAddressFamily == AF_INET6) {
      // TODO: IPv6 addresses are given as an array of byte values.
      r["host"] = SQL_TEXT(wtsClient->ClientAddress);
    }

    r["pid"] = INTEGER(-1);
    results.push_back(r);

    if (clientInfo != nullptr) {
      WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, clientInfo, count);
      clientInfo = nullptr;
    }
    if (sessionInfo != nullptr) {
      WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, sessionInfo, count);
      sessionInfo = nullptr;
    }
  }

  if (pSessionInfo != nullptr) {
    WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, pSessionInfo, count);
    pSessionInfo = nullptr;
  }

  return results;
}
}
}
