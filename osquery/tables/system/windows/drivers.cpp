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
#include <psapi.h>
#include <initguid.h>
// clang-format on
#include <Devpkey.h>
#include <Devpropdef.h>
#include <SetupAPI.h>

#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"
#include "osquery/tables/system/windows/services.h"

namespace osquery {
namespace tables {

const std::map<std::string, DEVPROPKEY> kDeviceProps = {
    {"name", DEVPKEY_NAME},
    {"description", DEVPKEY_Device_DriverDesc},
    {"service", DEVPKEY_Device_Service},
    {"version", DEVPKEY_Device_DriverVersion},
    {"inf", DEVPKEY_Device_DriverInfPath},
    {"class", DEVPKEY_Device_Class},
    {"status", DEVPKEY_Device_DevNodeStatus},
    {"key", DEVPKEY_Device_Driver},
    {"provider", DEVPKEY_Device_DriverProvider},
    {"install_date", DEVPKEY_Device_DriverDate }};
QueryData genDrivers(QueryContext& context) {
  QueryData results;

  auto closeInfoSet = [](auto infoSet) {
    SetupDiDestroyDeviceInfoList(infoSet);
  };
  std::unique_ptr<void, decltype(closeInfoSet)> devInfoSet(
      SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_ALLCLASSES), closeInfoSet);
  if (devInfoSet.get() == INVALID_HANDLE_VALUE) {
    TLOG << "Error getting device handle. Error code " + GetLastError();
    return results;
  }

  DWORD devIndex = 0;
  SP_DEVINFO_DATA devInfo;
  devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
  while (TRUE == SetupDiEnumDeviceInfo(devInfoSet.get(), devIndex, &devInfo)) {
    Row r;
    for (const auto& elem : kDeviceProps) {
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
          LOG(WARNING)
              << "Error getting buffer size for device property. Error code: " +
                     err;
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
                    GetLastError();
        continue;
      }

      if (devPropType == DEVPROP_TYPE_UINT32) {
        auto val = std::to_string(*(PUINT32)drvBuff.get());
        if (!val.empty()) {
          r[elem.first] = val;
        }
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
    devIndex++;
  }

  auto err = GetLastError();
  if (err != ERROR_NO_MORE_ITEMS) {
    LOG(WARNING) << "Error enumerating devices, results may be incomplete. "
                    "Error code: " +
                        err;
  }
  return results;
}
} // namespace tables
} // namespace osquery
