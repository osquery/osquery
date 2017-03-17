/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winsvc.h>

#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

const std::string kSvcStartType[] = {
    "BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"};

const std::string kSvcStatus[] = {"UNKNOWN",
                                  "STOPPED",
                                  "START_PENDING",
                                  "STOP_PENDING",
                                  "RUNNING",
                                  "CONTINUE_PENDING",
                                  "PAUSE_PENDING",
                                  "PAUSED"};

const std::map<int, std::string> kServiceType = {
    {0x00000010, "OWN_PROCESS"},
    {0x00000020, "SHARE_PROCESS"},
    {0x00000100, "INTERACTIVE_PROCESS"},
    {0x00000110, "OWN_PROCESS(Interactive)"},
    {0x00000120, "SHARE_PROCESS(Interactive)"}};

bool QuerySvcInfo(const SC_HANDLE& schScManager,
                  ENUM_SERVICE_STATUS_PROCESS& svc,
                  Row& r) {
  DWORD cbBufSize = 0;

  auto schService =
      OpenService(schScManager, svc.lpServiceName, SERVICE_QUERY_CONFIG);

  if (schService == nullptr) {
    TLOG << "OpenService failed (" << GetLastError() << ")";
    return FALSE;
  }

  QueryServiceConfig(schService, nullptr, 0, &cbBufSize);
  auto lpsc = (LPQUERY_SERVICE_CONFIG)malloc(cbBufSize);
  if (!QueryServiceConfig(schService, lpsc, cbBufSize, &cbBufSize)) {
    TLOG << "QueryServiceConfig failed (" << GetLastError() << ")";
  }

  QueryServiceConfig2(
      schService, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &cbBufSize);
  auto lpsd = (LPSERVICE_DESCRIPTION)malloc(cbBufSize);
  if (!QueryServiceConfig2(schService,
                           SERVICE_CONFIG_DESCRIPTION,
                           (LPBYTE)lpsd,
                           cbBufSize,
                           &cbBufSize)) {
    TLOG << "QueryServiceConfig2 failed (" << GetLastError() << ")";
  }

  r["name"] = SQL_TEXT(svc.lpServiceName);
  r["display_name"] = SQL_TEXT(svc.lpDisplayName);
  r["status"] = SQL_TEXT(kSvcStatus[svc.ServiceStatusProcess.dwCurrentState]);
  r["pid"] = INTEGER(svc.ServiceStatusProcess.dwProcessId);
  r["win32_exit_code"] = INTEGER(svc.ServiceStatusProcess.dwWin32ExitCode);
  r["service_exit_code"] =
      INTEGER(svc.ServiceStatusProcess.dwServiceSpecificExitCode);
  r["start_type"] = SQL_TEXT(kSvcStartType[lpsc->dwStartType]);
  r["path"] = SQL_TEXT(lpsc->lpBinaryPathName);
  r["user_account"] = SQL_TEXT(lpsc->lpServiceStartName);

  if (lpsd->lpDescription != nullptr) {
    r["description"] = SQL_TEXT(lpsd->lpDescription);
  }

  if (kServiceType.count(lpsc->dwServiceType) > 0) {
    r["service_type"] = SQL_TEXT(kServiceType.at(lpsc->dwServiceType));
  } else {
    r["service_type"] = SQL_TEXT("UNKNOWN");
  }

  QueryData regResults;
  queryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" +
               r["name"] + "\\Parameters",
           regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "ServiceDll") {
      r["module_path"] = SQL_TEXT(aKey.at("data"));
    }
  }

  free(lpsc);
  free(lpsd);
  CloseServiceHandle(schService);
  return TRUE;
}

QueryData genServices(QueryContext& context) {
  void* buf = nullptr;
  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  QueryData results;

  auto schScManager = OpenSCManager(nullptr, nullptr, GENERIC_READ);
  if (schScManager == nullptr) {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
    return {};
  }

  (void)EnumServicesStatusEx(schScManager,
                             SC_ENUM_PROCESS_INFO,
                             SERVICE_WIN32,
                             SERVICE_STATE_ALL,
                             nullptr,
                             0,
                             &bytesNeeded,
                             &serviceCount,
                             nullptr,
                             nullptr);

  buf = malloc(bytesNeeded);
  if (EnumServicesStatusEx(schScManager,
                           SC_ENUM_PROCESS_INFO,
                           SERVICE_WIN32,
                           SERVICE_STATE_ALL,
                           (LPBYTE)buf,
                           bytesNeeded,
                           &bytesNeeded,
                           &serviceCount,
                           nullptr,
                           nullptr)) {
    ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)buf;
    for (DWORD i = 0; i < serviceCount; ++i) {
      Row r;
      if (QuerySvcInfo(schScManager, services[i], r)) {
        results.push_back(r);
      }
    }
  } else {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
  }

  free(buf);
  CloseServiceHandle(schScManager);
  return results;
}
}
}
