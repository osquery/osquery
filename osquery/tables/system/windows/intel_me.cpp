/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <memory>
#include <unordered_set>

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

const unsigned char kGetFirmwareVersionCommand[4] = {0};

struct HdevInfoDeleter final {
  using pointer = HDEVINFO;

  void operator()(pointer handle) {
    SetupDiDestroyDeviceInfoList(handle);
  }
};

struct HandleDeleter final {
  using pointer = HANDLE;

  void operator()(pointer handle) {
    CloseHandle(handle);
  }
};

template <typename DeleterFunctor>
struct GenericHandleDeleter final {
  using pointer = typename DeleterFunctor::pointer;

  void operator()(pointer handle) {
    if (handle == INVALID_HANDLE_VALUE) {
      return;
    }

    DeleterFunctor deleter;
    deleter(handle);
  }
};

using DeviceInformationSet =
    std::unique_ptr<HdevInfoDeleter::pointer,
                    GenericHandleDeleter<HdevInfoDeleter>>;

using DeviceHandle = std::unique_ptr<HandleDeleter::pointer,
                                     GenericHandleDeleter<HandleDeleter>>;

osquery::Status getDeviceInformationSet(DeviceInformationSet& dev_info_set,
                                        const GUID* guid_filter) {
  dev_info_set.reset();

  auto filter = const_cast<LPGUID>(&HECI_INTERFACE_GUID);

  HDEVINFO handle = SetupDiGetClassDevs(
      filter, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

  if (handle == INVALID_HANDLE_VALUE) {
    return osquery::Status::failure(
        "No device found matching the Intel ME device setup class. Error: " +
        std::to_string(GetLastError()));
  }

  dev_info_set.reset(handle);
  return osquery::Status(0);
}

osquery::Status getDeviceInterfacePath(
    std::string& dev_interface_path,
    const DeviceInformationSet& dev_info_set,
    const SP_DEVICE_INTERFACE_DATA& dev_interface) {
  dev_interface_path = {};

  auto dev_interface_copy = dev_interface;

  DWORD buffer_size = 0U;
  SetupDiGetDeviceInterfaceDetail(dev_info_set.get(),
                                  &dev_interface_copy,
                                  nullptr,
                                  0,
                                  &buffer_size,
                                  nullptr);

  auto err = GetLastError();
  if (err != ERROR_INSUFFICIENT_BUFFER) {
    return osquery::Status::failure(
        "Failed to acquire the device interface details. Error: " +
        std::to_string(err));
  }

  if (buffer_size <= sizeof(DWORD)) {
    return osquery::Status::failure(
        "Invalid buffer size returned for the device interface detail "
        "structure");
  }

  std::vector<std::uint8_t> buffer(static_cast<std::size_t>(buffer_size));

  auto device_details =
      reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA*>(buffer.data());

  device_details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

  if (!SetupDiGetDeviceInterfaceDetail(dev_info_set.get(),
                                       &dev_interface_copy,
                                       device_details,
                                       buffer_size,
                                       nullptr,
                                       nullptr)) {
    return osquery::Status::failure(
        "Failed to acquire the device interface details. Error: " +
        std::to_string(err));
  }

  std::string path;
  path.assign(device_details->DevicePath, buffer.size() - sizeof(DWORD));

  if (std::strlen(path.c_str()) == 0U) {
    return osquery::Status::failure(
        "Invalid path returned for the given device interface; the string is "
        "empty");
  }

  dev_interface_path = std::move(path);
  path.clear();

  return osquery::Status(0);
}

osquery::Status enumerateHECIDeviceInterfacePaths(
    std::unordered_set<std::string>& dev_path_list) {
  dev_path_list = {};

  // Get a device information set containing all the device interfaces matching
  // our device setup class GUID
  DeviceInformationSet dev_info_set;
  auto status = getDeviceInformationSet(dev_info_set, &HECI_INTERFACE_GUID);
  if (!status.ok()) {
    return status;
  }

  // Go through each item in the device information set, collecting the path for
  // for each device interface
  std::unordered_set<std::string> path_list;

  for (DWORD member_index = 0U; true; member_index++) {
    SP_DEVICE_INTERFACE_DATA dev_interface = {};
    dev_interface.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    if (!SetupDiEnumDeviceInterfaces(dev_info_set.get(),
                                     nullptr,
                                     &HECI_INTERFACE_GUID,
                                     member_index,
                                     &dev_interface)) {
      auto err = GetLastError();
      if (err != ERROR_NO_MORE_ITEMS) {
        LOG(WARNING) << "An error has occurred while querying a device. Error: "
                     << GetLastError();
        continue;
      }

      break;
    }

    std::string dev_interface_path = {};
    status =
        getDeviceInterfacePath(dev_interface_path, dev_info_set, dev_interface);

    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
      continue;
    }

    path_list.insert(dev_interface_path);
  }

  if (path_list.empty()) {
    return osquery::Status::failure("No path found for the HECI device");
  }

  dev_path_list = std::move(path_list);
  path_list.clear();

  return osquery::Status(0);
}

osquery::Status openDeviceInterface(DeviceHandle& device_handle,
                                    const std::string& dev_interface_path) {
  device_handle.reset();

  auto device = CreateFile(dev_interface_path.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           OPEN_EXISTING,
                           0,
                           nullptr);

  if (device == INVALID_HANDLE_VALUE) {
    return osquery::Status::failure(
        "Failed to open handle to the following device: " + dev_interface_path +
        "Error: " + std::to_string(GetLastError()));
  }

  device_handle.reset(device);
  return osquery::Status(0);
}

osquery::Status queryDeviceVersion(std::string& version,
                                   const std::string& dev_interface_path) {
  version = {};

  DeviceHandle device;
  auto status = openDeviceInterface(device, dev_interface_path);
  if (!status.ok()) {
    return status;
  }

  // Attempt to open the device
  auto open_command_copy = tables::kMEIUpdateGUID;
  auto open_command_size = static_cast<DWORD>(open_command_copy.size());

  tables::mei_response response = {};
  if (!DeviceIoControl(device.get(),
                       INTEL_ME_WINDOWS_IOCTL,
                       open_command_copy.data(),
                       open_command_size,
                       &response,
                       sizeof(response),
                       nullptr,
                       nullptr)) {
    auto err = GetLastError();
    if (err == ERROR_GEN_FAILURE) {
      return osquery::Status::failure(
          "The driver is already in use by another client and can't be queried "
          "at this time");
    }

    return osquery::Status::failure("Failed to query the driver. Error: " +
                                    std::to_string(err));
  }

  // Validate the response
  bool invalid_response = false;
  if (response.maxlen < sizeof(tables::mei_version)) {
    LOG(WARNING) << "Invalid maxlen size returned: " +
                        std::to_string(response.maxlen);

    invalid_response = true;
  }

  if (kExpectedMaxLenValues.count(response.maxlen) == 0U) {
    LOG(WARNING) << "The returned maxlen field value is unexpected: "
                 << response.maxlen;

    invalid_response = true;
  }

  if (response.version != 0x01) {
    LOG(WARNING) << "Unexpected response version: "
                 << std::to_string(response.version)
                 << ". Continuing anyway...";
  }

  if (invalid_response) {
    return osquery::Status::failure(
        "Invalid response received from the device");
  }

  // Request the firmware version
  if (!WriteFile(device.get(),
                 kGetFirmwareVersionCommand,
                 sizeof(kGetFirmwareVersionCommand),
                 nullptr,
                 nullptr)) {
    return osquery::Status::failure(
        "Failed to send the firmware version query to the device");
  }

  std::vector<std::uint8_t> read_buffer(response.maxlen);
  DWORD bytes_read = 0U;

  if (!ReadFile(device.get(),
                read_buffer.data(),
                static_cast<DWORD>(read_buffer.size()),
                &bytes_read,
                nullptr)) {
    return osquery::Status::failure("Failed to acquire the device response");
  }

  if (static_cast<size_t>(bytes_read) < sizeof(tables::mei_version)) {
    return osquery::Status::failure(
        "Invalid device response when attempting to acquire the firmware "
        "version");
  }

  // Convert the numeric version fields to string
  auto raw_version =
      reinterpret_cast<const tables::mei_version*>(read_buffer.data());

  version = std::to_string(raw_version->major) + '.' +
            std::to_string(raw_version->minor) + '.' +
            std::to_string(raw_version->hotfix) + '.' +
            std::to_string(raw_version->build);

  return osquery::Status(0);
}
} // namespace

namespace tables {
void getHECIDriverVersion(QueryData& results) {
  results = {};

  std::unordered_set<std::string> dev_path_list;
  auto status = enumerateHECIDeviceInterfacePaths(dev_path_list);
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return;
  }

  if (dev_path_list.empty()) {
    LOG(INFO) << "No Intel ME device found";
    return;
  }

  for (const auto& dev_path : dev_path_list) {
    std::string version = {};
    status = queryDeviceVersion(version, dev_path);
    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
      continue;
    }

    Row r = {};
    r["version"] = std::move(version);
    results.push_back(std::move(r));
  }
}

QueryData getIntelMEInfo(QueryContext& context) {
  QueryData results;
  getHECIDriverVersion(results);

  return results;
}
} // namespace tables
} // namespace osquery
