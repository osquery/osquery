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
// clang-format off
#include <Windows.h>
#include <Winsvc.h>
#include <initguid.h>
// clang-format on
#include <cfgmgr32.h>
#include <Devpkey.h>
#include <Devpropdef.h>
#include <SetupAPI.h>

#include <string>
#include <boost/regex.hpp>

#include <osquery/core.h>

#include <osquery/sql.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {
namespace tables {

const auto freePtr = [](auto ptr) { free(ptr); };
static inline void logWarn(const std::string& msg,
                           const DWORD& code = GetLastError()) {
  LOG(WARNING) << msg + " Error code: " + std::to_string(code);
}

QueryData genDrivers(QueryContext& context) {
  QueryData results;
  CHAR systemRoot[MAX_PATH];
  GetSystemDirectory(systemRoot, MAX_PATH);

  auto closeInfoSet = [](auto infoSet) {
    SetupDiDestroyDeviceInfoList(infoSet);
  };
  std::unique_ptr<void, decltype(closeInfoSet)> devInfoSet(
      SetupDiGetClassDevs(
          nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT),
      closeInfoSet);
  if (devInfoSet.get() == INVALID_HANDLE_VALUE) {
    logWarn("Error getting device handle.");
    return results;
  }

  SP_DEVINFO_LIST_DETAIL_DATA devInfoDetail;
  devInfoDetail.cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA);
  if (SetupDiGetDeviceInfoListDetail(devInfoSet.get(), &devInfoDetail) ==
      FALSE) {
    logWarn("Failed to get device info details.");
    return results;
  }

  DWORD devIndex = 0;
  SP_DEVINFO_DATA devInfo;
  devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
  SP_DEVINSTALL_PARAMS installParams;
  ZeroMemory(&installParams, sizeof(SP_DEVINSTALL_PARAMS));
  installParams.cbSize = sizeof(SP_DEVINSTALL_PARAMS);
  installParams.FlagsEx |=
      DI_FLAGSEX_ALLOWEXCLUDEDDRVS | DI_FLAGSEX_INSTALLEDDRIVER;

  while (TRUE == SetupDiEnumDeviceInfo(devInfoSet.get(), devIndex, &devInfo)) {
    if (SetupDiSetDeviceInstallParams(
            devInfoSet.get(), &devInfo, &installParams) == FALSE) {
      logWarn(
          "Failed to set device install params, driver listing may take longer "
          "than usual.");
    }

    char devId[MAX_DEVICE_ID_LEN];
    if (CM_Get_Device_ID(devInfo.DevInst, devId, MAX_DEVICE_ID_LEN, 0) !=
        CR_SUCCESS) {
      logWarn("Failed to get device ID.");
      devIndex++;
      continue;
    }

    SP_DRVINFO_DATA drvInfo;
    drvInfo.cbSize = sizeof(SP_DRVINFO_DATA);
    SP_DRVINFO_DETAIL_DATA drvInfoDetail;
    drvInfoDetail.cbSize = sizeof(SP_DRVINFO_DETAIL_DATA);
    if (SetupDiBuildDriverInfoList(
            devInfoSet.get(), &devInfo, SPDIT_CLASSDRIVER) == FALSE) {
      logWarn("Failed to build driver info list.");
      devIndex++;
      continue;
    }

    if (SetupDiEnumDriverInfo(
            devInfoSet.get(), &devInfo, SPDIT_CLASSDRIVER, 0, &drvInfo) ==
        FALSE) {
      auto err = GetLastError();
      if (err == ERROR_NO_MORE_ITEMS) {
        devIndex++;
        continue;
      } else {
        logWarn("Failed to enumerate driver info/", err);
        devIndex++;
        continue;
      }
    }
    if (SetupDiGetDriverInfoDetail(devInfoSet.get(),
                                   &devInfo,
                                   &drvInfo,
                                   &drvInfoDetail,
                                   sizeof(SP_DRVINFO_DETAIL_DATA),
                                   nullptr) == FALSE) {
      auto err = GetLastError();
      if (err != ERROR_INSUFFICIENT_BUFFER) {
        logWarn("Failed to enumerate driver detailed info.", err);
        devIndex++;
        continue;
      }
    }

    Row r;
    r["device_id"] = devId;
    r["inf"] = drvInfoDetail.InfFileName;
    r["provider"] = drvInfo.ProviderName;
    r["manufacturer"] = drvInfo.MfgName;
    r["date"] = std::to_string(osquery::filetimeToUnixtime(drvInfo.DriverDate));
    r["description"] = drvInfo.Description;
    ULARGE_INTEGER version;
    version.QuadPart = drvInfo.DriverVersion;
    r["version"] = std::to_string(HIWORD(version.HighPart)) + "." +
                   std::to_string(HIWORD(version.LowPart)) + "." +
                   std::to_string(LOWORD(version.HighPart)) + "." +
                   std::to_string(LOWORD(version.LowPart));

    const std::map<std::string, DEVPROPKEY> props = {
        {"device_name", DEVPKEY_NAME},
        {"service", DEVPKEY_Device_Service},
        {"driver_key", DEVPKEY_Device_Driver},
        {"class", DEVPKEY_Device_Class}};
    for (const auto& elem : props) {
      DWORD buffSize;
      DEVPROPTYPE devPropType;
      auto ret = SetupDiGetDevicePropertyW(devInfoSet.get(),
                                           &devInfo,
                                           &elem.second,
                                           &devPropType,
                                           nullptr,
                                           0,
                                           &buffSize,
                                           0);
      auto err = GetLastError();
      if (err != ERROR_INSUFFICIENT_BUFFER) {
        if (err != ERROR_NOT_FOUND) {
          logWarn("Error getting buffer size for device property.", err);
        }
        continue;
      }

      std::unique_ptr<BYTE, decltype(freePtr)> drvBuff(
          static_cast<PBYTE>(malloc(buffSize)), freePtr);
      if (drvBuff == nullptr) {
        LOG(WARNING) << "Failed to malloc for driver info buffer.";
        continue;
      }

      ret = SetupDiGetDevicePropertyW(devInfoSet.get(),
                                      &devInfo,
                                      &elem.second,
                                      &devPropType,
                                      drvBuff.get(),
                                      buffSize,
                                      nullptr,
                                      0);
      if (ret == FALSE) {
        logWarn("Error retrieving device property.");
        continue;
      }

      if (devPropType == DEVPROP_TYPE_UINT32) {
        r[elem.first] = std::to_string(*(PUINT32)drvBuff.get());
      } else if (devPropType == DEVPROP_TYPE_INT32) {
        r[elem.first] = std::to_string(*(PINT32)drvBuff.get());
      } else if (devPropType == DEVPROP_TYPE_STRING) {
        std::wstring name((PWCHAR)drvBuff.get());
        r[elem.first] = std::string(name.begin(), name.end());
      } else if (devPropType == DEVPROP_TYPE_FILETIME) {
        r[elem.first] = std::to_string(
            osquery::filetimeToUnixtime(*(PFILETIME)drvBuff.get()));
      } else {
        LOG(WARNING) << "Unhandled device property type: " + devPropType;
        continue;
      }
    }
    r["driver_key"].insert(
        0, "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\");
    if (!r["service"].empty()) {
      r["service_key"] =
          "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" +
          r["service"];
      SQL sql("SELECT data FROM registry WHERE path = '" + r["service_key"] +
              "\\ImagePath'");
      if (sql.rows().size() == 1) {
        auto path = sql.rows().at(0).at("data");
        if (!path.empty()) {
          r["image"] = systemRoot + boost::regex_replace(
                                        path, boost::regex("^.*[Ss]ystem32"), "");
        }
      }
    }

    results.emplace_back(r);
    ZeroMemory(&devInfo, sizeof(SP_DEVINFO_DATA));
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    devIndex++;
  }
  auto err = GetLastError();
  if (err != ERROR_NO_MORE_ITEMS) {
    logWarn("Error enumerating devices, results may be incomplete.");
  }
  return results;
}
} // namespace tables
} // namespace osquery
