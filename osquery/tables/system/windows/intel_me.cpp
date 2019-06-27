/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// clang-format off
#include <osquery/utils/system/system.h>
#include <SetupAPI.h>
// clang-format on
#include <initguid.h>
#include <tchar.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/tables/system/intel_me.hpp>

namespace osquery {
namespace {
const std::unordered_set<size_t> kExpectedMaxLenValues = {512U, 4096U};
} // namespace

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
    LOG(WARNING) << "Failed to open MEI device with " << GetLastError();
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
    LOG(WARNING) << "Could not locate HECI driver";
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
    LOG(WARNING) << "Failed to open handle to device path with "
                 << GetLastError();
    return;
  }

  unsigned long ioctlConnectClient = INTEL_ME_WINDOWS_IOCTL;

  // Response data from driver open.
  struct mei_response response;
  ret = DeviceIoControl(driver,
                        ioctlConnectClient,
                        (LPVOID)kMEIUpdateGUID.data(),
                        static_cast<DWORD>(kMEIUpdateGUID.size()),
                        &response,
                        sizeof(response),
                        nullptr,
                        nullptr);

  if (ret == 0) {
    auto last_error = GetLastError();
    if (last_error == ERROR_GEN_FAILURE) {
      LOG(WARNING)
          << "The driver is already in use by another client and can't be "
             "queried at this time";
    } else {
      LOG(WARNING) << "Device IOCTL call failed with " << last_error;
    }

    CloseHandle(driver);
    return;
  }

  if (response.maxlen < sizeof(mei_version)) {
    LOG(WARNING) << "Invalid maxlen size: " << response.maxlen;
    return;
  } else if (kExpectedMaxLenValues.count(response.maxlen) == 0U) {
    LOG(WARNING) << "The returned maxlen field value is unexpected: "
                 << response.maxlen;
  }

  unsigned char fw_cmd[4] = {0};
  ret = WriteFile(
      driver, static_cast<void*>(fw_cmd), sizeof(fw_cmd), nullptr, nullptr);
  if (ret != TRUE) {
    LOG(WARNING) << "HECI driver write failed with " << GetLastError();
  }

  // Response from FirmwareUpdate HECI GUID.
  std::vector<std::uint8_t> read_buffer(response.maxlen);
  DWORD bytes_read = 0U;

  ret = ReadFile(driver,
                 read_buffer.data(),
                 static_cast<DWORD>(read_buffer.size()),
                 &bytes_read,
                 nullptr);

  CloseHandle(driver);

  if (ret != TRUE) {
    std::fill(read_buffer.begin(), read_buffer.end(), 0U);
    LOG(WARNING) << "HECI driver read failed with " << GetLastError();
  } else if (static_cast<size_t>(bytes_read) < sizeof(mei_version)) {
    // This is unlikely
    std::fill(read_buffer.begin(), read_buffer.end(), 0U);
    LOG(WARNING) << "The driver has not returned enough bytes";
  }

  auto version = reinterpret_cast<const mei_version*>(read_buffer.data());

  Row r;
  r["version"] = std::to_string(version->major) + '.' +
                 std::to_string(version->minor) + '.' +
                 std::to_string(version->hotfix) + '.' +
                 std::to_string(version->build);

  results.push_back(r);
}

QueryData getIntelMEInfo(QueryContext& context) {
  QueryData results;
  getHECIDriverVersion(results);
  return results;
}
} // namespace tables
} // namespace osquery
