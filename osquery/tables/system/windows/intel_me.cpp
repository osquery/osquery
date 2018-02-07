/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <Windows.h>
#include <SetupAPI.h>
// clang-format on
#include <initguid.h>
#include <tchar.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/intel_me.hpp"

#define DECLARE_TABLE_IMPLEMENTATION_intel_me_info
#include <generated/tables/tbl_intel_me_info_defs.hpp>

namespace osquery {
namespace tables {

DEFINE_GUID(HECI_INTERFACE_GUID,
            0xE2D1FF34,
            0x3458,
            0x49A9,
            0x88,
            0xDA,
            0x8E,
            0x69,
            0x15,
            0xCE,
            0x9B,
            0xE5);

void getHECIDriverVersion(QueryData& results) {
  // Find all devices that have our interface handle for device info
  auto guid = const_cast<LPGUID>(&HECI_INTERFACE_GUID);
  HDEVINFO deviceInfo = SetupDiGetClassDevs(
      guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

  if (deviceInfo == INVALID_HANDLE_VALUE) {
    VLOG(1) << "Failed to open MEI device with " << GetLastError();
    return;
  }

  SP_DEVICE_INTERFACE_DATA interfaceData;
  interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

  // This device path is the output from the driver search logic here.
  std::string devPath;

  unsigned long index = 0;
  auto ret = SetupDiEnumDeviceInterfaces(
      deviceInfo, nullptr, guid, index, &interfaceData);
  while (ret == TRUE) {
    unsigned long detailSize = 0;
    if (!SetupDiGetDeviceInterfaceDetail(
            deviceInfo, &interfaceData, nullptr, 0, &detailSize, nullptr)) {
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        continue;
      }
    }

    auto deviceDetails = static_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(
        LocalAlloc(LPTR, detailSize));

    if (deviceDetails != nullptr) {
      deviceDetails->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
      if (SetupDiGetDeviceInterfaceDetail(deviceInfo,
                                          &interfaceData,
                                          deviceDetails,
                                          detailSize,
                                          nullptr,
                                          nullptr)) {
        devPath = deviceDetails->DevicePath;
      }
      LocalFree(deviceDetails);
    }

    ret = SetupDiEnumDeviceInterfaces(
        deviceInfo, nullptr, guid, ++index, &interfaceData);
  }

  SetupDiDestroyDeviceInfoList(deviceInfo);

  // HECI driver was not found
  if (devPath.empty()) {
    VLOG(1) << "Could not locate HECI driver";
    return;
  }

  HANDLE driver = CreateFile(devPath.c_str(),
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr,
                             OPEN_EXISTING,
                             0,
                             nullptr);
  if (driver == INVALID_HANDLE_VALUE) {
    VLOG(1) << "Failed to open handle to device path with " << GetLastError();
    return;
  }

  unsigned long ioctlConnectClient = INTEL_ME_WINDOWS_IOCTL;

  // Response data from driver open.
  struct mei_response response;
  // Response from FirmwareUpdate HECI GUID.
  struct mei_version version;

  ret = DeviceIoControl(driver,
                        ioctlConnectClient,
                        (LPVOID)kMEIUpdateGUID.data(),
                        static_cast<DWORD>(kMEIUpdateGUID.size()),
                        &response,
                        sizeof(response),
                        nullptr,
                        nullptr);

  if (ret == 0) {
    VLOG(1) << "Device IOCTL call failed with " << GetLastError();
    CloseHandle(driver);
    return;
  }

  unsigned char fw_cmd[4] = {0};
  ret = WriteFile(
      driver, static_cast<void*>(fw_cmd), sizeof(fw_cmd), nullptr, nullptr);
  if (ret != TRUE) {
    VLOG(1) << "HECI driver write failed with " << GetLastError();
  }

  memset(&version, 0, sizeof(version));
  ret = ReadFile(driver, &version, sizeof(version), nullptr, nullptr);
  if (ret != TRUE) {
    VLOG(1) << "HECI driver read failed with " << GetLastError();
  }

  CloseHandle(driver);

  Row r;
  r["version"] = std::to_string(version.major) + '.' +
                 std::to_string(version.minor) + '.' +
                 std::to_string(version.hotfix) + '.' +
                 std::to_string(version.build);

  results.push_back(r);
}

QueryData getIntelMEInfo(QueryContext& context) {
  QueryData results;
  getHECIDriverVersion(results);
  return results;
}
}
}
