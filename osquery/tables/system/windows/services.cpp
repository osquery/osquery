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

class WinSvc : private only_movable {
 public:
  explicit WinSvc(SC_HANDLE scmHandle, ENUM_SERVICE_STATUS_PROCESS serviceName);
  WinSvc(WinSvc&&) = default;
  WinSvc& operator=(WinSvc&&) = default;
  ~WinSvc();

 public:
  Status status();
  bool ok();
  Row result();

 private:
  SC_HANDLE scHandle_;
  Row result_;
  Status status_;
};

WinSvc::WinSvc(SC_HANDLE scmHandle, ENUM_SERVICE_STATUS_PROCESS svc) {
  scHandle_ = OpenService(scmHandle, svc.lpServiceName, SERVICE_QUERY_CONFIG);
  if (scHandle_ == nullptr) {
    status_ = Status(GetLastError(), "Failed to open service handle");
    return;
  }

  DWORD cbBufSize;
  (void)QueryServiceConfig(scHandle_, nullptr, 0, &cbBufSize);
  std::unique_ptr<QUERY_SERVICE_CONFIG> lpsc(
      static_cast<LPQUERY_SERVICE_CONFIG>(malloc(cbBufSize)));
  if (0 == QueryServiceConfig(scHandle_, lpsc.get(), cbBufSize, &cbBufSize)) {
    status_ = Status(GetLastError(), "Failed to query service config");
    return;
  }

  (void)QueryServiceConfig2(
      scHandle_, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &cbBufSize);
  std::unique_ptr<SERVICE_DESCRIPTION> lpsd(
      static_cast<LPSERVICE_DESCRIPTION>(malloc(cbBufSize)));
  if (0 == QueryServiceConfig2(scHandle_,
                               SERVICE_CONFIG_DESCRIPTION,
                               (LPBYTE)lpsd.get(),
                               cbBufSize,
                               &cbBufSize)) {
    status_ = Status(GetLastError(), "Failed to query service description");
    return;
  }

  result_["name"] = SQL_TEXT(svc.lpServiceName);
  result_["display_name"] = SQL_TEXT(svc.lpDisplayName);
  result_["status"] =
      SQL_TEXT(kSvcStatus[svc.ServiceStatusProcess.dwCurrentState]);
  result_["pid"] = INTEGER(svc.ServiceStatusProcess.dwProcessId);
  result_["win32_exit_code"] =
      INTEGER(svc.ServiceStatusProcess.dwWin32ExitCode);
  result_["service_exit_code"] =
      INTEGER(svc.ServiceStatusProcess.dwServiceSpecificExitCode);
  result_["start_type"] = SQL_TEXT(kSvcStartType[lpsc->dwStartType]);
  result_["path"] = SQL_TEXT(lpsc->lpBinaryPathName);
  result_["user_account"] = SQL_TEXT(lpsc->lpServiceStartName);

  if (lpsd->lpDescription != nullptr) {
    result_["description"] = SQL_TEXT(lpsd->lpDescription);
  }

  if (kServiceType.count(lpsc->dwServiceType) > 0) {
    result_["service_type"] = SQL_TEXT(kServiceType.at(lpsc->dwServiceType));
  } else {
    result_["service_type"] = SQL_TEXT("UNKNOWN");
  }

  QueryData regResults;
  queryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" +
               result_["name"] + "\\Parameters",
           regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "ServiceDll") {
      result_["module_path"] = SQL_TEXT(aKey.at("data"));
    }
  }
}

WinSvc::~WinSvc() {
  CloseServiceHandle(scHandle_);
}

Row WinSvc::result() {
  return result_;
}

Status WinSvc::status() {
  return status_;
}

class WinSvcQuery : private only_movable {
 public:
  WinSvcQuery();
  WinSvcQuery(WinSvcQuery&&) = default;
  WinSvcQuery& operator=(WinSvcQuery&&) = default;
  ~WinSvcQuery();

 public:
  QueryData results();
  Status status();

 private:
  SC_HANDLE scmHandle_;
  QueryData results_;
  Status status_;
};

QueryData WinSvcQuery::results() {
  return results_;
}

Status WinSvcQuery::status() {
  return status_;
}

WinSvcQuery::WinSvcQuery() {
  scmHandle_ = OpenSCManager(nullptr, nullptr, GENERIC_READ);
  if (scmHandle_ == nullptr) {
    status_ = Status(GetLastError(),
                     "Failed to connect to Service Connection Manager");
    return;
  }

  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  (void)EnumServicesStatusEx(scmHandle_,
                             SC_ENUM_PROCESS_INFO,
                             SERVICE_WIN32,
                             SERVICE_STATE_ALL,
                             nullptr,
                             0,
                             &bytesNeeded,
                             &serviceCount,
                             nullptr,
                             nullptr);

  std::unique_ptr<ENUM_SERVICE_STATUS_PROCESS[]> buf(
      static_cast<ENUM_SERVICE_STATUS_PROCESS*>(malloc(bytesNeeded)));
  if (0 == EnumServicesStatusEx(scmHandle_,
                                SC_ENUM_PROCESS_INFO,
                                SERVICE_WIN32,
                                SERVICE_STATE_ALL,
                                (LPBYTE)buf.get(),
                                bytesNeeded,
                                &bytesNeeded,
                                &serviceCount,
                                nullptr,
                                nullptr)) {
    status_ = Status(GetLastError(), "Failed to enumerate services");
    return;
  }
  for (size_t i = 0; i < serviceCount; i++) {
    results_.push_back(WinSvc(scmHandle_, buf[i]).result());
  }
}

WinSvcQuery::~WinSvcQuery() {
  CloseServiceHandle(scmHandle_);
}

QueryData genServices(QueryContext& context) {
  WinSvcQuery q;
  if (q.status().ok()) {
    return q.results();
  } else {
    LOG(WARNING) << q.status().getMessage();
    return QueryData();
  }
}
} // namespace tables
} // namespace osquery
