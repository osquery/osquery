/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/env.h>
#include <osquery/utils/system/system.h>

#include <Winsvc.h>

#include <string>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

const auto freePtr = [](auto ptr) { free(ptr); };
const auto closeServiceHandle = [](SC_HANDLE sch) { CloseServiceHandle(sch); };

using svc_descr_t = std::unique_ptr<SERVICE_DESCRIPTION, decltype(freePtr)>;
using svc_handle_t = std::unique_ptr<SC_HANDLE__, decltype(closeServiceHandle)>;
using svc_query_t = std::unique_ptr<QUERY_SERVICE_CONFIG, decltype(freePtr)>;
using enum_svc_status_t =
    std::unique_ptr<ENUM_SERVICE_STATUS_PROCESS[], decltype(freePtr)>;

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

static inline Status getService(const SC_HANDLE& scmHandle,
                                const ENUM_SERVICE_STATUS_PROCESS& svc,
                                QueryData& results) {
  Row r;
  svc_handle_t svcHandle(
      OpenService(scmHandle, svc.lpServiceName, SERVICE_QUERY_CONFIG),
      closeServiceHandle);
  if (svcHandle == nullptr) {
    return Status(GetLastError(), "Failed to open service handle");
  }

  DWORD cbBufSize;
  (void)QueryServiceConfig(svcHandle.get(), nullptr, 0, &cbBufSize);
  auto err = GetLastError();
  if (ERROR_INSUFFICIENT_BUFFER != err) {
    return Status(err, "Failed to query size of service config buffer");
  }

  svc_query_t lpsc(static_cast<LPQUERY_SERVICE_CONFIG>(malloc(cbBufSize)),
                   freePtr);
  if (lpsc == nullptr) {
    return Status(1, "Failed to malloc service config buffer");
  }

  auto ret =
      QueryServiceConfig(svcHandle.get(), lpsc.get(), cbBufSize, &cbBufSize);
  if (ret == 0) {
    return Status(GetLastError(), "Failed to query service config");
  }

  try {
    (void)QueryServiceConfig2(
        svcHandle.get(), SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &cbBufSize);
    err = GetLastError();
    if (ERROR_INSUFFICIENT_BUFFER == err) {
      svc_descr_t lpsd(static_cast<LPSERVICE_DESCRIPTION>(malloc(cbBufSize)),
                       freePtr);
      if (lpsd == nullptr) {
        throw std::runtime_error("failed to malloc service description buffer");
      }
      ret = QueryServiceConfig2(svcHandle.get(),
                                SERVICE_CONFIG_DESCRIPTION,
                                (LPBYTE)lpsd.get(),
                                cbBufSize,
                                &cbBufSize);
      if (ret == 0) {
        std::stringstream ss;
        ss << "failed to query size of service description buffer, error: "
           << GetLastError();
        throw std::runtime_error(ss.str());
      }
      if (lpsd->lpDescription != nullptr) {
        r["description"] = SQL_TEXT(wstringToString(lpsd->lpDescription));
      }
    } else if (ERROR_MUI_FILE_NOT_FOUND != err) {
      // Bug in Windows 10 with CDPUserSvc_63718, just ignore description
      throw std::runtime_error("failed to query service description");
    }
  } catch (const std::runtime_error& e) {
    LOG(WARNING) << svc.lpServiceName << ": " << e.what();
  }

  r["name"] = SQL_TEXT(wstringToString(svc.lpServiceName));
  r["display_name"] = SQL_TEXT(wstringToString(svc.lpDisplayName));
  r["status"] = kSvcStatus[svc.ServiceStatusProcess.dwCurrentState];
  r["pid"] = INTEGER(svc.ServiceStatusProcess.dwProcessId);
  r["win32_exit_code"] = INTEGER(svc.ServiceStatusProcess.dwWin32ExitCode);
  r["service_exit_code"] =
      INTEGER(svc.ServiceStatusProcess.dwServiceSpecificExitCode);
  r["start_type"] = SQL_TEXT(kSvcStartType[lpsc->dwStartType]);
  r["path"] = SQL_TEXT(wstringToString(lpsc->lpBinaryPathName));
  r["user_account"] = SQL_TEXT(wstringToString(lpsc->lpServiceStartName));

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
      auto module_path = aKey.at("data");
      if (const auto expanded_path = expandEnvString(module_path)) {
        module_path = *expanded_path;
      }

      r["module_path"] = SQL_TEXT(module_path);
    }
  }

  results.push_back(r);
  return Status::success();
}

static inline Status getServices(QueryData& results) {
  svc_handle_t scmHandle(OpenSCManager(nullptr, nullptr, GENERIC_READ),
                         closeServiceHandle);
  if (scmHandle == nullptr) {
    return Status(GetLastError(),
                  "Failed to connect to Service Connection Manager");
  }

  DWORD bytesNeeded;
  DWORD serviceCount;
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
  auto err = GetLastError();
  if (ERROR_MORE_DATA != err) {
    return Status(err, "Failed to query service list buffer size");
  }

  enum_svc_status_t lpSvcBuf(
      static_cast<ENUM_SERVICE_STATUS_PROCESS*>(malloc(bytesNeeded)), freePtr);
  if (lpSvcBuf == nullptr) {
    return Status(1, "Failed to malloc service buffer");
  }

  auto ret = EnumServicesStatusEx(scmHandle.get(),
                                  SC_ENUM_PROCESS_INFO,
                                  SERVICE_WIN32,
                                  SERVICE_STATE_ALL,
                                  (LPBYTE)lpSvcBuf.get(),
                                  bytesNeeded,
                                  &bytesNeeded,
                                  &serviceCount,
                                  nullptr,
                                  nullptr);
  if (ret == 0) {
    return Status(GetLastError(), "Failed to enumerate services");
  }

  for (size_t i = 0; i < serviceCount; i++) {
    auto s = getService(scmHandle.get(), lpSvcBuf[i], results);
    if (!s.ok()) {
      LOG(WARNING) << s.getMessage();
    }
  }

  return Status::success();
}

QueryData genServices(QueryContext& context) {
  QueryData results;
  auto status = getServices(results);
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    results = QueryData();
  }
  return results;
}
} // namespace tables
} // namespace osquery
