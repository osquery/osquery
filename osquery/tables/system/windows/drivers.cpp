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

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/services.h"

namespace osquery {
namespace tables {

const std::map<std::string, DEVPROPKEY> kDeviceProps = {
    {"name", DEVPKEY_NAME},
    {"description", DEVPKEY_Device_DriverDesc},
    {"service", DEVPKEY_Device_Service},
    {"version", DEVPKEY_Device_DriverVersion},
    {"class", DEVPKEY_Device_Class},
    {"provider", DEVPKEY_Device_DriverProvider},
    {"install_date", DEVPKEY_Device_DriverDate}};

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  auto closeInfoSet = [](auto infoSet) {
    SetupDiDestroyDeviceInfoList(infoSet);
  };
  std::unique_ptr<void, decltype(closeInfoSet)> devInfoSet(
      SetupDiGetClassDevs(
          nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT),
      closeInfoSet);
  if (devInfoSet.get() == INVALID_HANDLE_VALUE) {
    LOG(WARNING) << "Error getting device handle. Error code: " +
                        std::to_string(GetLastError());
    return results;
  }

  SP_DEVINFO_LIST_DETAIL_DATA devInfoDetail;
  devInfoDetail.cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA);
  if (SetupDiGetDeviceInfoListDetail(devInfoSet.get(), &devInfoDetail) ==
      FALSE) {
    LOG(WARNING) << "Failed to get device info details. Error code: " +
                        std::to_string(GetLastError());
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
      LOG(WARNING) << "Failed to set device install params. Error code: " +
                          std::to_string(GetLastError());
    }

    auto devId = std::make_unique<TCHAR[]>(MAX_DEVICE_ID_LEN);
    if (devId == nullptr) {
      LOG(WARNING) << "Failed to malloc for device ID.";
      return results;
    }
    if (CM_Get_Device_ID(devInfo.DevInst, devId.get(), MAX_DEVICE_ID_LEN, 0) !=
        CR_SUCCESS) {
      LOG(WARNING) << "Failed to get device ID. Error code: " +
                          std::to_string(GetLastError());
      return results;
    }

    SP_DRVINFO_DATA drvInfo;
    drvInfo.cbSize = sizeof(SP_DRVINFO_DATA);
    SP_DRVINFO_DETAIL_DATA drvInfoDetail;
    drvInfoDetail.cbSize = sizeof(SP_DRVINFO_DETAIL_DATA);
    if (SetupDiBuildDriverInfoList(
            devInfoSet.get(), &devInfo, SPDIT_CLASSDRIVER) == FALSE) {
      LOG(WARNING) << "Failed to build driver info list. Error code: " +
                          std::to_string(GetLastError());
      return results;
    }

    if (SetupDiEnumDriverInfo(
            devInfoSet.get(), &devInfo, SPDIT_CLASSDRIVER, 0, &drvInfo) ==
        FALSE) {
      auto err = GetLastError();
      if (err == ERROR_NO_MORE_ITEMS) {
        devIndex++;
        continue;
      } else {
        LOG(WARNING) << "Failed to enumerate driver info. Error code: " +
                            std::to_string(GetLastError());
        return results;
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
        LOG(WARNING)
            << "Failed to enumerate driver detailed info. Error code: " +
                   std::to_string(GetLastError());
        return results;
      }
    }

    Row r;
    r["device_id"] = devId.get();
    r["inf"] = drvInfoDetail.InfFileName;
    for (const auto& elem : kDeviceProps) {
      DWORD buffSize;
      DEVPROPTYPE
      devPropType;
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
          LOG(WARNING)
              << "Error getting buffer size for device property. Error code: " +
                     std::to_string(err);
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
        TLOG << "Error retrieving device property. Error code: " +
                    std::to_string(GetLastError());
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
    results.emplace_back(r);
    ZeroMemory(&devInfo, sizeof(SP_DEVINFO_DATA));
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    devIndex++;
  }
  auto err = GetLastError();
  if (err != ERROR_NO_MORE_ITEMS) {
    LOG(WARNING) << "Error enumerating devices, results may be incomplete. "
                    "Error code: " +
                        std::to_string(err);
  }
  return results;
}
} // namespace tables
} // namespace osquery
