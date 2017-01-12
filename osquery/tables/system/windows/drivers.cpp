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

  auto schService =
      OpenService(schScManager, svc.lpServiceName, SERVICE_QUERY_CONFIG);

  if (schService == nullptr) {
    TLOG << "OpenService failed (" << GetLastError() << ")";
    return;
  }

  QueryServiceConfig(schService, nullptr, 0, &cbBufSize);
  auto lpsc = static_cast<LPQUERY_SERVICE_CONFIG>(malloc(cbBufSize));
  if (QueryServiceConfig(schService, lpsc, cbBufSize, &cbBufSize) != 0) {
    TLOG << "QueryServiceConfig failed (" << GetLastError() << ")";
  }

  r["name"] = SQL_TEXT(svc.lpServiceName);
  r["display_name"] = SQL_TEXT(svc.lpDisplayName);
  r["status"] = SQL_TEXT(kDrvStatus[svc.ServiceStatusProcess.dwCurrentState]);
  r["start_type"] = SQL_TEXT(kDrvStartType[lpsc->dwStartType]);

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
  queryKey("HKEY_LOCAL_MACHINE",
           "SYSTEM\\CurrentControlSet\\Services\\" + r["name"],
           regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "Owners") {
      r["inf"] = SQL_TEXT(aKey.at("data"));
    }
  }

  // Remove the driver from loadedDrivers list to avoid duplicates
  loadedDrivers.erase(svc.lpServiceName);
  results.push_back(r);
  free(lpsc);
  CloseServiceHandle(schService);
}

void enumLoadedDrivers(std::map<std::string, std::string>& loadedDrivers) {
  DWORD bytesNeeded = 0;
  int driversCount = 0;

  auto ret = EnumDeviceDrivers(nullptr, 0, &bytesNeeded);
  auto drvBaseAddr = static_cast<LPVOID*>(malloc(bytesNeeded));

  if (drvBaseAddr == nullptr) {
    TLOG << "enumLoadedDrivers failed to allocate required memory ("
         << bytesNeeded << ")";
    return;
  }

  ret = EnumDeviceDrivers(drvBaseAddr, bytesNeeded, &bytesNeeded);

  driversCount = bytesNeeded / sizeof(drvBaseAddr[0]);

  if (ret && (driversCount > 0)) {
    auto driverPath = static_cast<LPSTR>(malloc(MAX_PATH + 1));
    auto driverName = static_cast<LPSTR>(malloc(MAX_PATH + 1));

    ZeroMemory(driverPath, MAX_PATH + 1);
    ZeroMemory(driverName, MAX_PATH + 1);

    for (size_t i = 0; i < driversCount; i++) {
      if (GetDeviceDriverBaseName(drvBaseAddr[i], driverName, MAX_PATH) != 0) {
        if (GetDeviceDriverFileName(drvBaseAddr[i], driverPath, MAX_PATH) !=
            0) {
          // Removing file extension
          auto fileExtension = strrchr(driverName, '.');
          *fileExtension = '\0';
          loadedDrivers[driverName] = driverPath;
        } else {
          loadedDrivers[driverName] = "";
        }
      } else {
        TLOG << "GetDeviceDriverFileName failed (" << GetLastError() << ")";
      }
    }

    free(driverPath);
    free(driverName);
  } else {
    TLOG << "EnumDeviceDrivers failed; array size needed is" << bytesNeeded;
  }

  free(drvBaseAddr);
}

QueryData genDrivers(QueryContext& context) {
  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  std::map<std::string, std::string> loadedDrivers;
  QueryData results;

  // Get All Loaded Drivers including ones managed by SCM
  enumLoadedDrivers(loadedDrivers);

  auto schScManager = OpenSCManager(nullptr, nullptr, GENERIC_READ);
  if (schScManager == nullptr) {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
    return {};
  }

  EnumServicesStatusEx(schScManager,
                       SC_ENUM_PROCESS_INFO,
                       SERVICE_DRIVER,
                       SERVICE_STATE_ALL,
                       nullptr,
                       0,
                       &bytesNeeded,
                       &serviceCount,
                       nullptr,
                       nullptr);

  auto buf = static_cast<PVOID>(malloc(bytesNeeded));
  if (EnumServicesStatusEx(schScManager,
                           SC_ENUM_PROCESS_INFO,
                           SERVICE_DRIVER,
                           SERVICE_STATE_ALL,
                           (LPBYTE)buf,
                           bytesNeeded,
                           &bytesNeeded,
                           &serviceCount,
                           nullptr,
                           nullptr) != 0) {
    auto services = static_cast<ENUM_SERVICE_STATUS_PROCESS*>(buf);
    for (DWORD i = 0; i < serviceCount; ++i) {
      queryDrvInfo(schScManager, services[i], loadedDrivers, results);
    }
  } else {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
  }

  free(buf);
  CloseServiceHandle(schScManager);

  for (const auto& element : loadedDrivers) {
    Row r;
    r["name"] = element.first;
    r["path"] = element.second;
    r["status"] = SQL_TEXT(kDrvStatus[4]);
    results.push_back(r);
  }

  return results;
}
}
}
