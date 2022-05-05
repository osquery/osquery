/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <Wtsapi32.h>
#include <winsock2.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

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

  PWTS_SESSION_INFO_1W pSessionInfo;
  unsigned long count;
  /*
   * As per the MSDN:
   * This parameter is reserved. Always set this parameter to one.
   */
  unsigned long level = 1;
  auto res = WTSEnumerateSessionsExW(
      WTS_CURRENT_SERVER_HANDLE, &level, 0, &pSessionInfo, &count);

  if (res == 0) {
    return results;
  }

  for (size_t i = 0; i < count; i++) {
    if (pSessionInfo[i].State != WTSActive || pSessionInfo[i].SessionId == 0) {
      // https://docs.microsoft.com/en-gb/windows/win32/api/wtsapi32/ne-wtsapi32-wts_connectstate_class
      // The only state for a user logged in is WTSActive and session 0 is the
      // non-interactive system session
      continue;
    }

    Row r;

    LPWSTR sessionInfo = nullptr;
    DWORD bytesRet = 0;
    res = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                      pSessionInfo[i].SessionId,
                                      WTSSessionInfo,
                                      &sessionInfo,
                                      &bytesRet);
    if (res == 0 || sessionInfo == nullptr) {
      VLOG(1) << "Error querying WTS session information (" << GetLastError()
              << ")";
      continue;
    }

    const auto wtsSession = reinterpret_cast<WTSINFOW*>(sessionInfo);
    r["user"] = SQL_TEXT(wstringToString(wtsSession->UserName));
    r["type"] = SQL_TEXT(kSessionStates.at(pSessionInfo[i].State));
    r["tty"] = pSessionInfo[i].pSessionName == nullptr
                   ? ""
                   : wstringToString(pSessionInfo[i].pSessionName);

    FILETIME utcTime = {0};
    unsigned long long unixTime = 0;
    utcTime.dwLowDateTime = wtsSession->ConnectTime.LowPart;
    utcTime.dwHighDateTime = wtsSession->ConnectTime.HighPart;
    if (utcTime.dwLowDateTime != 0 || utcTime.dwHighDateTime != 0) {
      unixTime = filetimeToUnixtime(utcTime);
    }
    r["time"] = BIGINT(unixTime);

    LPWSTR clientInfo = nullptr;
    bytesRet = 0;
    res = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                      pSessionInfo[i].SessionId,
                                      WTSClientInfo,
                                      &clientInfo,
                                      &bytesRet);
    if (res == 0 || clientInfo == nullptr) {
      VLOG(1) << "Error querying WTS session information (" << GetLastError()
              << ")";
      results.push_back(r);
      WTSFreeMemory(sessionInfo);
      continue;
    }

    auto wtsClient = reinterpret_cast<WTSCLIENTA*>(clientInfo);
    if (wtsClient->ClientAddressFamily == AF_INET) {
      r["host"] = std::to_string(wtsClient->ClientAddress[0]) + "." +
                  std::to_string(wtsClient->ClientAddress[1]) + "." +
                  std::to_string(wtsClient->ClientAddress[2]) + "." +
                  std::to_string(wtsClient->ClientAddress[3]);
    } else if (wtsClient->ClientAddressFamily == AF_INET6) {
      // TODO: IPv6 addresses are given as an array of byte values.
      auto addr = reinterpret_cast<const char*>(wtsClient->ClientAddress);
      r["host"] = std::string(addr, CLIENTADDRESS_LENGTH);
    }

    r["pid"] = INTEGER(-1);

    if (clientInfo != nullptr) {
      WTSFreeMemory(clientInfo);
      clientInfo = nullptr;
      wtsClient = nullptr;
    }

    const auto sidBuf = getSidFromAccountName(wtsSession->UserName);

    if (sessionInfo != nullptr) {
      WTSFreeMemory(sessionInfo);
      sessionInfo = nullptr;
    }

    if (sidBuf == nullptr) {
      VLOG(1) << "Error converting username to SID";
      results.push_back(r);
      continue;
    }

    const auto sidStr = psidToString(reinterpret_cast<SID*>(sidBuf.get()));
    r["sid"] = SQL_TEXT(sidStr);

    const auto hivePath = "HKEY_USERS\\" + sidStr;
    r["registry_hive"] = SQL_TEXT(hivePath);

    results.push_back(r);
  }

  if (pSessionInfo != nullptr) {
    WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, pSessionInfo, count);
    pSessionInfo = nullptr;
  }

  return results;
}
} // namespace tables
} // namespace osquery
