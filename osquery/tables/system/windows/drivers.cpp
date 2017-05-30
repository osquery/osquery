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
#include <psapi.h>
#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/windows/registry.h"
#include "osquery/tables/system/windows/services.h"

namespace osquery {
namespace tables {

const std::string kDrvStartType[] = {
    "BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"};

const std::string kDrvStatus[] = {"UNKNOWN",
                                  "STOPPED",
                                  "START_PENDING",
                                  "STOP_PENDING",
                                  "RUNNING",
                                  "CONTINUE_PENDING",
                                  "PAUSE_PENDING",
                                  "PAUSED"};

const std::map<int, std::string> kDriverType = {
    {0x00000001, "KERNEL"}, {0x00000002, "FILE_SYSTEM"},
};

void queryDrvInfo(const SC_HANDLE& schScManager,
                  ENUM_SERVICE_STATUS_PROCESS& svc,
                  std::map<std::string, std::string>& loadedDrivers,
                  QueryData& results) {
  Row r;
  DWORD cbBufSize = 0;

  svc_handle_t schService(
      OpenService(schScManager, svc.lpServiceName, SERVICE_QUERY_CONFIG),
      closeServiceHandle);

  if (schService == nullptr) {
    TLOG << "OpenService failed (" << GetLastError() << ")";
    return;
  }

  (void)QueryServiceConfig(schService.get(), nullptr, 0, &cbBufSize);
  svc_query_t lpsc(static_cast<LPQUERY_SERVICE_CONFIG>(malloc(cbBufSize)),
                   freePtr);
  if (lpsc == nullptr) {
    TLOG << "Failed to query service config (" << GetLastError() << ")";
    return;
  }
  if (QueryServiceConfig(schService.get(), lpsc.get(), cbBufSize, &cbBufSize) !=
      0) {
    TLOG << "QueryServiceConfig failed (" << GetLastError() << ")";
  }
  r["start_type"] = ret == 0 ? "" : SQL_TEXT(kDrvStartType[lpsc->dwStartType]);

  // If SCM can't get 'path' of the driver then use the path
  // available in loadedDrivers list
  if (strlen(lpsc->lpBinaryPathName) <= 0) {
    r["path"] = loadedDrivers[svc.lpServiceName];
  } else {
    r["path"] = SQL_TEXT(lpsc->lpBinaryPathName);
  }

  if (kDriverType.count(lpsc->dwServiceType) > 0) {
    r["type"] = SQL_TEXT(kDriverType.at(lpsc->dwServiceType));
  } else {
    r["type"] = SQL_TEXT("UNKNOWN");
  }

  QueryData regResults;
  queryKey(
      "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + r["name"],
      regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "Owners") {
      r["inf"] = SQL_TEXT(aKey.at("data"));
    }
    std::string major_version = "0";
    std::string minor_version = "0";
    if (aKey.at("name") == "DriverMajorVersion") {
      major_version = SQL_TEXT(aKey.at("data"));
    }
    if (aKey.at("name") == "DriverMinorVersion") {
      minor_version = SQL_TEXT(aKey.at("data"));
    }
    r["version"] = major_version + "." + minor_version;
  }

  // Remove the driver from loadedDrivers list to avoid duplicates
  loadedDrivers.erase(svc.lpServiceName);
  results.push_back(r);
}

void enumLoadedDrivers(std::map<std::string, std::string>& loadedDrivers) {
  unsigned long bytesNeeded = 0;
  auto driversCount = 0;

  auto ret = EnumDeviceDrivers(nullptr, 0, &bytesNeeded);
  std::unique_ptr<LPVOID[], decltype(freePtr)> drvBaseAddr(
      static_cast<LPVOID*>(malloc(bytesNeeded)), freePtr);
  if (drvBaseAddr == nullptr) {
    TLOG << "enumLoadedDrivers failed to allocate required memory ("
         << bytesNeeded << ")";
    return;
  }

  ret = EnumDeviceDrivers(drvBaseAddr.get(), bytesNeeded, &bytesNeeded);

  driversCount = bytesNeeded / sizeof(drvBaseAddr[0]);
  if (ret && (driversCount > 0)) {
    std::unique_ptr<CHAR, decltype(freePtr)> driverPath(
        static_cast<LPSTR>(malloc(MAX_PATH + 1)), freePtr);
    std::unique_ptr<CHAR, decltype(freePtr)> driverName(
        static_cast<LPSTR>(malloc(MAX_PATH + 1)), freePtr);

    if (driverPath == nullptr || driverName == nullptr) {
      TLOG << "Failed to allocate memory for driver details (" << (MAX_PATH + 1)
           << ")";
      return;
    }

    ZeroMemory(driverPath.get(), MAX_PATH + 1);
    ZeroMemory(driverName.get(), MAX_PATH + 1);

    for (size_t i = 0; i < driversCount; i++) {
      if (GetDeviceDriverBaseName(drvBaseAddr[i], driverName.get(), MAX_PATH) !=
          0) {
        if (GetDeviceDriverFileName(
                drvBaseAddr[i], driverPath.get(), MAX_PATH) != 0) {
          // Removing file extension
          auto fileExtension = strrchr(driverName.get(), '.');
          *fileExtension = '\0';
          loadedDrivers[driverName.get()] = driverPath.get();
        } else {
          loadedDrivers[driverName.get()] = "";
        }
      } else {
        TLOG << "GetDeviceDriverFileName failed (" << GetLastError() << ")";
      }
    }
  } else {
    TLOG << "EnumDeviceDrivers failed; array size needed is" << bytesNeeded;
  }
}

QueryData genDrivers(QueryContext& context) {
  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  std::map<std::string, std::string> loadedDrivers;
  QueryData results;

  // Get All Loaded Drivers including ones managed by SCM
  enumLoadedDrivers(loadedDrivers);

  svc_handle_t schScManager(OpenSCManager(nullptr, nullptr, GENERIC_READ),
                            closeServiceHandle);
  if (schScManager == nullptr) {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
    return {};
  }

  EnumServicesStatusEx(schScManager.get(),
                       SC_ENUM_PROCESS_INFO,
                       SERVICE_DRIVER,
                       SERVICE_STATE_ALL,
                       nullptr,
                       0,
                       &bytesNeeded,
                       &serviceCount,
                       nullptr,
                       nullptr);

  enum_svc_status_t services(
      static_cast<ENUM_SERVICE_STATUS_PROCESS*>(malloc(bytesNeeded)), freePtr);
  if (services == nullptr) {
    return results;
  }
  if (EnumServicesStatusEx(schScManager.get(),
                           SC_ENUM_PROCESS_INFO,
                           SERVICE_DRIVER,
                           SERVICE_STATE_ALL,
                           (LPBYTE)services.get(),
                           bytesNeeded,
                           &bytesNeeded,
                           &serviceCount,
                           nullptr,
                           nullptr) != 0) {
    for (DWORD i = 0; i < serviceCount; ++i) {
      queryDrvInfo(schScManager.get(), services[i], loadedDrivers, results);
    }
  } else {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
  }

  for (const auto& element : loadedDrivers) {
    Row r;
    r["name"] = element.first;
    r["path"] = element.second;
    r["status"] = SQL_TEXT(kDrvStatus[4]);
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
