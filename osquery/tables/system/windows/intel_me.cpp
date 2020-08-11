/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <unordered_set>

// clang-format off
#include <osquery/utils/system/system.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <SetupAPI.h>
// clang-format on

#include <boost/format.hpp>

#include <initguid.h>
#include <tchar.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/tables/system/intel_me.hpp>

// The AMT documentation can be found at the following address:
// https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm

namespace osquery {
namespace {
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

// clang-format off
const std::vector<std::vector<std::uint8_t>> kConnectDeviceCommandData = {
  // Interface type 0
  { 0x15, 0x67, 0x6A, 0x8E, 0xBC, 0x9A, 0x43, 0x40, 0x88, 0xEF, 0x9E, 0x39, 0xC6, 0xF6, 0x3E, 0x0F },

  // Interface type 1
  { 0x84, 0x35, 0x21, 0x55, 0x29, 0x9A, 0x16, 0x49, 0xBA, 0xDF, 0x0F, 0xB7, 0xED, 0x68, 0x2A, 0xEB },

  // Interface type 2
  { 0xE8, 0xCD, 0x9D, 0x30, 0xB1, 0xCC, 0x62, 0x40, 0x8F, 0x78, 0x60, 0x01, 0x15, 0xA3, 0x43, 0x27 }
};
// clang-format on

const std::uint32_t kGetHECIVersionCommand = 0x8000E000U;
const std::uint32_t kConnectDeviceCommand = 0x8000E004U;

const std::vector<std::uint8_t>
    kGetFirmareVersionCommandForInterfaceTypes0And1 = {0xFF, 0x02, 0x00, 0x00};

const std::vector<std::uint8_t> kGetFirmareVersionCommandForInterfaceType2 = {
    0x00, 0x00, 0x00, 0x00};

const std::uint32_t kGetFirmareVersionCommandForInterfaceType2Reply =
    0x00000001U;

// It is best to generate a report of your own system using the Intel
// detection tool and then match the versions with the returned data.
// The tool can be found here:
// https://downloadcenter.intel.com/download/27150/INTEL-SA-00086-Detection-Tool
struct IntelMEInformation final {
  struct HECIVersion final {
    std::uint8_t major{0U};
    std::uint8_t minor{0U};
    std::uint8_t hotfix{0U};
    std::uint16_t build{0U};
  };

  struct ProtocolInformation final {
    std::size_t max_message_length{0U};
    std::uint8_t version{0U};
  };

  struct FirmwareVersionTypes0And1 final {
    struct VersionData final {
      std::uint16_t minor{0U};
      std::uint16_t major{0U};
      std::uint16_t build_number{0U};
      std::uint16_t hotfix{0U};
    };

    VersionData code;
    VersionData nftp;
    boost::optional<VersionData> fitc;
  };

  struct FirmwareVersionType2 final {
    std::uint32_t sku{0U};
    std::uint32_t pch_ver{0U};
    std::uint32_t vendor{0U};
    std::uint32_t last_fw_update_status{0U};
    std::uint32_t hw_sku{0U};

    std::uint16_t major{0U};
    std::uint16_t minor{0U};
    std::uint16_t build{0U};
    std::uint16_t revision{0U};
  };

  enum InterfaceType : int {
    InterfaceType_0,
    InterfaceType_1,
    InterfaceType_2,
    InterfaceType_Max
  };

  HECIVersion heci_version;
  ProtocolInformation protocol_information;
  InterfaceType interface_type;
  boost::variant<FirmwareVersionTypes0And1, FirmwareVersionType2> fw_version;
};

std::string printFirmareVersionData(
    const IntelMEInformation::FirmwareVersionTypes0And1::VersionData&
        version_data) {
  return (boost::format("Major: %d Minor: %d Build number: %d Hotfix: %d") %
          static_cast<int>(version_data.major) %
          static_cast<int>(version_data.minor) %
          static_cast<int>(version_data.build_number) %
          static_cast<int>(version_data.hotfix))
      .str();
}

std::string printHeciVersionData(
    const IntelMEInformation::HECIVersion& version_data) {
  return (boost::format("Major: %d Minor: %d Hotfix: %d Build number: %d") %
          static_cast<int>(version_data.major) %
          static_cast<int>(version_data.minor) %
          static_cast<int>(version_data.hotfix) %
          static_cast<int>(version_data.build))
      .str();
}

std::string printFirmwareVersion(
    const IntelMEInformation::FirmwareVersionTypes0And1& fw_version) {
  std::string fitc_version;
  if (fw_version.fitc) {
    fitc_version = printFirmareVersionData(fw_version.fitc.get());
  } else {
    fitc_version = "N/A";
  }

  return (boost::format(
              "VersionTypes0And1 { CODE { %s } NFTP { %s } FITC { %s } } ") %
          printFirmareVersionData(fw_version.code) %
          printFirmareVersionData(fw_version.nftp) % fitc_version)
      .str();
}

std::string printFirmwareVersion(
    const IntelMEInformation::FirmwareVersionType2& fw_version) {
  return (boost::format("VersionType2 { sku: %u pch_ver: %u vendor: %u "
                        "last_fw_update_status: %u hw_sku: %u major: %u minor: "
                        "%u build: %u revision: %u }") %
          fw_version.sku % fw_version.pch_ver % fw_version.vendor %
          fw_version.last_fw_update_status % fw_version.hw_sku %
          fw_version.major % fw_version.minor % fw_version.build %
          fw_version.revision)
      .str();
}

std::string printInterfaceType(
    const IntelMEInformation::InterfaceType& interface_type) {
  switch (interface_type) {
  case IntelMEInformation::InterfaceType_0:
    return "Type0 ";

  case IntelMEInformation::InterfaceType_1:
    return "Type1 ";

  case IntelMEInformation::InterfaceType_2:
    return "Type2 ";

  case IntelMEInformation::InterfaceType_Max:
  default:
    return "<INVALID>";
  }
}

std::string printIntelMEVersion(const IntelMEInformation& intel_me_info) {
  std::string general_information =
      (boost::format("HECI Version: %s Protocol Version: %d Max Message "
                     "Length: %u Interface Type: %s ") %
       printHeciVersionData(intel_me_info.heci_version) %
       static_cast<int>(intel_me_info.protocol_information.version) %
       intel_me_info.protocol_information.max_message_length %
       printInterfaceType(intel_me_info.interface_type))
          .str();

  std::string firmware_information;
  if (intel_me_info.interface_type == IntelMEInformation::InterfaceType_0 ||
      intel_me_info.interface_type == IntelMEInformation::InterfaceType_1) {
    const auto& fw_version =
        boost::get<IntelMEInformation::FirmwareVersionTypes0And1>(
            intel_me_info.fw_version);

    firmware_information = printFirmwareVersion(fw_version);

  } else {
    const auto& fw_version =
        boost::get<IntelMEInformation::FirmwareVersionType2>(
            intel_me_info.fw_version);

    firmware_information = printFirmwareVersion(fw_version);
  }

  return general_information + firmware_information;
}

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

using EventHandle = std::unique_ptr<HandleDeleter::pointer,
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
  return osquery::Status::success();
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

  std::wstring path;
  path.assign(device_details->DevicePath, buffer.size() - sizeof(DWORD));

  if (std::wcslen(path.c_str()) == 0U) {
    return osquery::Status::failure(
        "Invalid path returned for the given device interface; the string is "
        "empty");
  }

  dev_interface_path = wstringToString(path);
  return osquery::Status::success();
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

  for (DWORD member_index = 0U;; member_index++) {
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

  return osquery::Status::success();
}

osquery::Status openDeviceInterface(DeviceHandle& device_handle,
                                    const std::string& dev_interface_path) {
  device_handle.reset();

  auto device = CreateFile(stringToWstring(dev_interface_path).c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED,
                           nullptr);

  if (device == INVALID_HANDLE_VALUE) {
    return osquery::Status::failure(
        "Failed to open a handle to the following device interface: " +
        dev_interface_path + "Error: " + std::to_string(GetLastError()));
  }

  device_handle.reset(device);
  return osquery::Status::success();
}

osquery::Status queryHECIVersion(IntelMEInformation& intel_me_info,
                                 HANDLE device) {
  DWORD bytes_read = 0U;
  std::array<std::uint8_t, 5U> response;

  if (!DeviceIoControl(device,
                       kGetHECIVersionCommand,
                       nullptr,
                       0U,
                       response.data(),
                       static_cast<DWORD>(response.size()),
                       &bytes_read,
                       nullptr)) {
    auto err = GetLastError();
    return osquery::Status::failure(
        "Failed to determine the HECI version. Error: " + std::to_string(err));
  }

  if (bytes_read != response.size()) {
    return osquery::Status::failure(
        "The driver has returned an invalid number of bytes");
  }

  intel_me_info.heci_version.major = response.at(0);
  intel_me_info.heci_version.minor = response.at(1);
  intel_me_info.heci_version.hotfix = response.at(2);

  std::memcpy(&intel_me_info.heci_version.build, response.data() + 3U, 2U);
  return osquery::Status::success();
}

osquery::Status sendConnectDeviceCommand(
    IntelMEInformation::ProtocolInformation& protocol_information,
    HANDLE device,
    IntelMEInformation::InterfaceType interface_type) {
  protocol_information = {};

  // Determine what kind of request we have to send
  const std::vector<std::uint8_t>* connect_command_data = nullptr;

  switch (interface_type) {
  case IntelMEInformation::InterfaceType_0:
    connect_command_data = &kConnectDeviceCommandData.at(0);
    break;

  case IntelMEInformation::InterfaceType_1:
    connect_command_data = &kConnectDeviceCommandData.at(1);
    break;

  case IntelMEInformation::InterfaceType_2:
    connect_command_data = &kConnectDeviceCommandData.at(2);
    break;
  }

  if (connect_command_data == nullptr) {
    return osquery::Status::failure("Invalid open mode specified");
  }

  // Make a copy of the data, as DeviceIoControl expects it to be writable
  auto connect_command_data_copy = *connect_command_data;

  std::array<std::uint8_t, 5U> response;
  DWORD bytes_read = 0U;

  if (!DeviceIoControl(device,
                       kConnectDeviceCommand,
                       connect_command_data_copy.data(),
                       static_cast<DWORD>(connect_command_data_copy.size()),
                       response.data(),
                       static_cast<DWORD>(response.size()),
                       &bytes_read,
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

  if (bytes_read != 5U) {
    return osquery::Status::failure(
        "The driver has returned an invalid amount of bytes");
  }

  const std::uint8_t* base_ptr = response.data();
  std::memcpy(&protocol_information.max_message_length, base_ptr, 4U);
  base_ptr += 4U;

  std::memcpy(&protocol_information.version, base_ptr, 1U);

  return osquery::Status::success();
}

osquery::Status connectToHECIInterface(IntelMEInformation& intel_me_info,
                                       HANDLE device) {
  osquery::Status status;

  for (int i = IntelMEInformation::InterfaceType_0;
       i != IntelMEInformation::InterfaceType_Max;
       i++) {
    auto interface_type = static_cast<IntelMEInformation::InterfaceType>(i);

    status = sendConnectDeviceCommand(
        intel_me_info.protocol_information, device, interface_type);

    if (status.ok()) {
      intel_me_info.interface_type = interface_type;
      break;
    }
  }

  return status;
}

osquery::Status createEvent(EventHandle& event) {
  event.reset();

  {
    auto h = CreateEvent(nullptr, false, false, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      return osquery::Status::failure("Failed to create the event");
    }

    event.reset(h);
  }

  return osquery::Status::success();
}

osquery::Status sendHECIMessage(HANDLE device,
                                const std::uint8_t* buffer,
                                std::size_t buffer_size,
                                std::chrono::milliseconds timeout) {
  EventHandle event;
  auto status = createEvent(event);
  if (!status.ok()) {
    return status;
  }

  OVERLAPPED overlapped = {};
  overlapped.hEvent = event.get();

  DWORD bytes_written = 0U;
  if (!WriteFile(device,
                 buffer,
                 static_cast<DWORD>(buffer_size),
                 &bytes_written,
                 &overlapped) &&
      GetLastError() != ERROR_IO_PENDING) {
    return osquery::Status::failure("Failed to send the HECI message");
  }

  auto wait_status =
      WaitForSingleObject(event.get(), static_cast<DWORD>(timeout.count()));

  if (wait_status == WAIT_TIMEOUT) {
    return osquery::Status::failure("The operation has timed out");
  } else if (wait_status != WAIT_OBJECT_0) {
    return osquery::Status::failure("The operation has failed");
  }

  DWORD bytes_transferred = 0U;
  if (!GetOverlappedResult(device, &overlapped, &bytes_transferred, false) ||
      static_cast<std::size_t>(bytes_transferred) != buffer_size) {
    return osquery::Status::failure(
        "Not all the bytes in the message could be correctly transferred");
  }

  return osquery::Status::success();
}

osquery::Status receiveHECIMessage(std::vector<std::uint8_t>& buffer,
                                   HANDLE device,
                                   std::size_t max_message_length,
                                   std::chrono::milliseconds timeout) {
  EventHandle event;
  auto status = createEvent(event);
  if (!status.ok()) {
    return status;
  }

  OVERLAPPED overlapped = {};
  overlapped.hEvent = event.get();

  std::vector<std::uint8_t> temp_buffer(max_message_length);
  DWORD bytes_read = 0U;

  if (!ReadFile(device,
                temp_buffer.data(),
                static_cast<DWORD>(max_message_length),
                &bytes_read,
                &overlapped) &&
      GetLastError() != ERROR_IO_PENDING) {
    return osquery::Status::failure("Failed to receive the HECI message");
  }

  auto wait_status =
      WaitForSingleObject(event.get(), static_cast<DWORD>(timeout.count()));

  if (wait_status == WAIT_TIMEOUT) {
    return osquery::Status::failure("The operation has timed out");
  } else if (wait_status != WAIT_OBJECT_0) {
    return osquery::Status::failure("The operation has failed");
  }

  DWORD bytes_transferred = 0U;
  if (!GetOverlappedResult(device, &overlapped, &bytes_transferred, false) ||
      bytes_transferred == 0U) {
    return osquery::Status::failure("Failed to read the HECI message");
  }

  temp_buffer.resize(static_cast<std::size_t>(bytes_transferred));
  buffer = std::move(temp_buffer);

  return osquery::Status::success();
}

osquery::Status queryFirmwareVersionForInterfaceTypes0And1(
    IntelMEInformation& intel_me_info, HANDLE device) {
  auto status =
      sendHECIMessage(device,
                      kGetFirmareVersionCommandForInterfaceTypes0And1.data(),
                      kGetFirmareVersionCommandForInterfaceTypes0And1.size(),
                      std::chrono::milliseconds(4000U));

  if (!status.ok()) {
    return status;
  }

  std::vector<std::uint8_t> response;
  status =
      receiveHECIMessage(response,
                         device,
                         intel_me_info.protocol_information.max_message_length,
                         std::chrono::milliseconds(4000U));

  if (!status.ok()) {
    return status;
  }

  if (response.size() != 20U && response.size() != 28U) {
    return osquery::Status::failure("Invalid response size");
  }

  //  We always have 4 leading padding bytes
  const std::uint8_t* base_ptr = response.data() + 4U;

  IntelMEInformation::FirmwareVersionTypes0And1 fw_version;

  // The answer type depends on the amount of bytes we received
  if (response.size() >= 20U) {
    std::memcpy(&fw_version.code.minor, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.code.major, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.code.build_number, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.code.hotfix, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.nftp.minor, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.nftp.major, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.nftp.build_number, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fw_version.nftp.hotfix, base_ptr, 2U);
    base_ptr += 2U;
  }

  if (response.size() == 28U) {
    IntelMEInformation::FirmwareVersionTypes0And1::VersionData fitc_version;

    std::memcpy(&fitc_version.minor, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fitc_version.major, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fitc_version.build_number, base_ptr, 2U);
    base_ptr += 2U;

    std::memcpy(&fitc_version.hotfix, base_ptr, 2U);
    base_ptr += 2U;

    fw_version.fitc = fitc_version;
  }

  intel_me_info.fw_version = fw_version;

  return osquery::Status::success();
}

osquery::Status queryFirmwareVersionForInterfaceType2(
    IntelMEInformation& intel_me_info, HANDLE device) {
  auto status =
      sendHECIMessage(device,
                      kGetFirmareVersionCommandForInterfaceType2.data(),
                      kGetFirmareVersionCommandForInterfaceType2.size(),
                      std::chrono::milliseconds(4000U));

  if (!status.ok()) {
    return status;
  }

  std::vector<std::uint8_t> response;
  status =
      receiveHECIMessage(response,
                         device,
                         intel_me_info.protocol_information.max_message_length,
                         std::chrono::milliseconds(4000U));

  if (!status.ok()) {
    return status;
  }

  if (response.size() < 8U + 28U) {
    return osquery::Status::failure("Invalid response size: " +
                                    std::to_string(response.size()));
  }

  std::uint32_t error_code = 0U;
  std::memcpy(&error_code, response.data() + 4U, 4U);

  if (error_code != 0U) {
    return osquery::Status::failure("Invalid response received");
  }

  std::uint32_t reply = 0U;
  std::memcpy(&reply, response.data(), 4U);

  if (reply != kGetFirmareVersionCommandForInterfaceType2Reply) {
    return osquery::Status::failure("Invalid reply");
  }

  IntelMEInformation::FirmwareVersionType2 fw_version;

  const std::uint8_t* base_ptr = response.data() + 8U;
  std::memcpy(&fw_version.sku, base_ptr, 4U);
  base_ptr += 4U;

  std::memcpy(&fw_version.pch_ver, base_ptr, 4U);
  base_ptr += 4U;

  std::memcpy(&fw_version.vendor, base_ptr, 4U);
  base_ptr += 4U;

  std::memcpy(&fw_version.last_fw_update_status, base_ptr, 4U);
  base_ptr += 4U;

  std::memcpy(&fw_version.hw_sku, base_ptr, 4U);
  base_ptr += 4U;

  std::memcpy(&fw_version.major, base_ptr, 2U);
  base_ptr += 2U;

  std::memcpy(&fw_version.minor, base_ptr, 2U);
  base_ptr += 2U;

  std::memcpy(&fw_version.build, base_ptr, 2U);
  base_ptr += 2U;

  std::memcpy(&fw_version.revision, base_ptr, 2U);
  base_ptr += 2U;

  intel_me_info.fw_version = fw_version;
  return osquery::Status::success();
}

osquery::Status queryFirmwareVersion(IntelMEInformation& intel_me_info,
                                     HANDLE device) {
  using QueryFirmwareFunction =
      osquery::Status (*)(IntelMEInformation&, HANDLE);

  // clang-format off
  const std::unordered_map<IntelMEInformation::InterfaceType, QueryFirmwareFunction> kQueryFunctions = {
    { IntelMEInformation::InterfaceType_0, queryFirmwareVersionForInterfaceTypes0And1 },
    { IntelMEInformation::InterfaceType_1, queryFirmwareVersionForInterfaceTypes0And1 },
    { IntelMEInformation::InterfaceType_2, queryFirmwareVersionForInterfaceType2 }
  };
  // clang-format on

  auto it = kQueryFunctions.find(intel_me_info.interface_type);
  if (it == kQueryFunctions.end()) {
    return osquery::Status::failure("Invalid or unknown interface type");
  }

  const auto& query_function = it->second;
  return query_function(intel_me_info, device);
}

osquery::Status queryIntelMEDeviceInterface(
    IntelMEInformation& intel_me_info, const std::string& dev_interface_path) {
  intel_me_info = {};

  DeviceHandle device;
  auto status = openDeviceInterface(device, dev_interface_path);
  if (!status.ok()) {
    return status;
  }

  status = queryHECIVersion(intel_me_info, device.get());
  if (!status.ok()) {
    return status;
  }

  status = connectToHECIInterface(intel_me_info, device.get());
  if (!status.ok()) {
    return status;
  }

  status = queryFirmwareVersion(intel_me_info, device.get());
  if (!status.ok()) {
    return status;
  }

  return osquery::Status::success();
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
    IntelMEInformation intel_me_info;
    status = queryIntelMEDeviceInterface(intel_me_info, dev_path);
    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
      continue;
    }

    // It useful to dump some information to the user in case something
    // goes wrong with this table; it is of great help to developers when
    // looking for a similar piece of hardware to reproduce the bug
    VLOG(1) << printIntelMEVersion(intel_me_info);

    // Do not dump the whole structures; just get the essential version
    // information and ignore the rest
    std::string version = {};

    switch (intel_me_info.interface_type) {
    case IntelMEInformation::InterfaceType_0:
    case IntelMEInformation::InterfaceType_1: {
      const auto& fw_version =
          boost::get<IntelMEInformation::FirmwareVersionTypes0And1>(
              intel_me_info.fw_version);

      version += std::to_string(fw_version.code.major) + "." +
                 std::to_string(fw_version.code.minor) + "." +
                 std::to_string(fw_version.code.hotfix) + "." +
                 std::to_string(fw_version.code.build_number);

      break;
    }

    case IntelMEInformation::InterfaceType_2: {
      const auto& fw_version =
          boost::get<IntelMEInformation::FirmwareVersionType2>(
              intel_me_info.fw_version);

      version += std::to_string(fw_version.major) + "." +
                 std::to_string(fw_version.minor) + "." +
                 std::to_string(fw_version.revision) + "." +
                 std::to_string(fw_version.build);

      break;
    }

    default: {
      LOG(ERROR) << "Unrecognized Intel ME protocol/interface type";
      break;
    }
    }

    if (version.empty()) {
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
