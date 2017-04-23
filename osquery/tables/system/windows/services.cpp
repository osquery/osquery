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

typedef std::unique_ptr<SC_HANDLE__, std::function<void(SC_HANDLE)>>
    svc_handle_t;

void closeServiceHandle(SC_HANDLE sch) {
  if (sch != nullptr) {
    CloseServiceHandle(sch);
  }
}

static inline Status getService(const SC_HANDLE& scmHandle,
                                const ENUM_SERVICE_STATUS_PROCESS& svc,
                                Row& result) {
  svc_handle_t svcHandle(
      OpenService(scmHandle, svc.lpServiceName, SERVICE_QUERY_CONFIG),
      closeServiceHandle);
  if (svcHandle == nullptr) {
    return Status(GetLastError(), "Failed to open service handle");
  }

  DWORD cbBufSize;
  (void)QueryServiceConfig(svcHandle.get(), nullptr, 0, &cbBufSize);
  std::unique_ptr<QUERY_SERVICE_CONFIG> lpsc(
      static_cast<LPQUERY_SERVICE_CONFIG>(malloc(cbBufSize)));
  if (lpsc == nullptr) {
    return Status(1, "Failed to malloc service config buffer");
  }

  if (0 ==
      QueryServiceConfig(svcHandle.get(), lpsc.get(), cbBufSize, &cbBufSize)) {
    return Status(GetLastError(), "Failed to query service config");
  }

  (void)QueryServiceConfig2(
      svcHandle.get(), SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &cbBufSize);
  std::unique_ptr<SERVICE_DESCRIPTION> lpsd(
      static_cast<LPSERVICE_DESCRIPTION>(malloc(cbBufSize)));
  if (lpsd == nullptr) {
    return Status(1, "Failed to malloc service description buffer");
  }

  if (0 == QueryServiceConfig2(svcHandle.get(),
                               SERVICE_CONFIG_DESCRIPTION,
                               (LPBYTE)lpsd.get(),
                               cbBufSize,
                               &cbBufSize)) {
    // This can fail for unclear reasons
    LOG(WARNING) << "Error querying description for service " +
                        (std::string)svc.lpDisplayName;
  }

  result["name"] = SQL_TEXT(svc.lpServiceName);
  result["display_name"] = SQL_TEXT(svc.lpDisplayName);
  result["status"] =
      SQL_TEXT(kSvcStatus[svc.ServiceStatusProcess.dwCurrentState]);
  result["pid"] = INTEGER(svc.ServiceStatusProcess.dwProcessId);
  result["win32_exit_code"] = INTEGER(svc.ServiceStatusProcess.dwWin32ExitCode);
  result["service_exit_code"] =
      INTEGER(svc.ServiceStatusProcess.dwServiceSpecificExitCode);
  result["start_type"] = SQL_TEXT(kSvcStartType[lpsc->dwStartType]);
  result["path"] = SQL_TEXT(lpsc->lpBinaryPathName);
  result["user_account"] = SQL_TEXT(lpsc->lpServiceStartName);

  if (lpsd->lpDescription != nullptr) {
    result["description"] = SQL_TEXT(lpsd->lpDescription);
  }

  if (kServiceType.count(lpsc->dwServiceType) > 0) {
    result["service_type"] = SQL_TEXT(kServiceType.at(lpsc->dwServiceType));
  } else {
    result["service_type"] = SQL_TEXT("UNKNOWN");
  }

  QueryData regResults;
  queryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" +
               result["name"] + "\\Parameters",
           regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "ServiceDll") {
      result["module_path"] = SQL_TEXT(aKey.at("data"));
    }
  }

  return Status();
}

static inline Status getServices(QueryData& results) {
  svc_handle_t scmHandle(OpenSCManager(nullptr, nullptr, GENERIC_READ),
                         closeServiceHandle);
  if (scmHandle == nullptr) {
    return Status(GetLastError(),
                  "Failed to connect to Service Connection Manager");
  }

  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  (void)EnumServicesStatusEx(scmHandle.get(),
                             SC_ENUM_PROCESS_INFO,
                             SERVICE_WIN32,
                             SERVICE_STATE_ALL,
                             nullptr,
                             0,
                             &bytesNeeded,
                             &serviceCount,
                             nullptr,
                             nullptr);
  std::unique_ptr<ENUM_SERVICE_STATUS_PROCESS[]> lpSvcBuf(
      static_cast<ENUM_SERVICE_STATUS_PROCESS*>(malloc(bytesNeeded)));
  if (lpSvcBuf == nullptr) {
    return Status(1, "Failed to malloc service buffer");
  }

  if (0 == EnumServicesStatusEx(scmHandle.get(),
                                SC_ENUM_PROCESS_INFO,
                                SERVICE_WIN32,
                                SERVICE_STATE_ALL,
                                (LPBYTE)lpSvcBuf.get(),
                                bytesNeeded,
                                &bytesNeeded,
                                &serviceCount,
                                nullptr,
                                nullptr)) {
    return Status(GetLastError(), "Failed to enumerate services");
  }

  for (size_t i = 0; i < serviceCount; i++) {
    Row r;
    auto s = getService(scmHandle.get(), lpSvcBuf[i], r);
    if (!s.ok()) {
      return s;
    }
    results.push_back(r);
  }

  return Status();
}

QueryData genServices(QueryContext& context) {
  QueryData results;
  auto status = getServices(results);
  if (!status.ok()) {
    // Prefer no results to incomplete results
    LOG(WARNING) << status.getMessage();
    results = QueryData();
  }
  return results;
}
} // namespace tables
} // namespace osquery
