/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_map>

#include <Windows.h>

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/info/firmware.h>

namespace osquery {

namespace {

enum class WindowsFirmwareType : std::uint32_t {
  Bios = 1,
  Uefi = 2,
};

using GetFirmwareTypePtr = bool(WINAPI*)(WindowsFirmwareType* firmware_type);

GetFirmwareTypePtr locateGetFirmwareTypeProc() {
  auto kernel32_module = GetModuleHandleA("kernel32");
  if (kernel32_module == nullptr) {
    return nullptr;
  }

  auto addr =
      static_cast<void*>(GetProcAddress(kernel32_module, "GetFirmwareType"));

  if (addr == nullptr) {
    return nullptr;
  }

  return static_cast<GetFirmwareTypePtr>(addr);
}

boost::optional<FirmwareKind> queryFirmwareKind() {
  auto getFirmwareType = locateGetFirmwareTypeProc();
  if (getFirmwareType == nullptr) {
    LOG(ERROR) << "The kernel32.dll!GetFirmwareType function was not found";
    return boost::none;
  }

  WindowsFirmwareType window_firmware_type;
  if (!getFirmwareType(&window_firmware_type)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "Failed to query the firmware type: "
               << errorDwordToString(error_code);

    return boost::none;
  }

  switch (window_firmware_type) {
  case WindowsFirmwareType::Uefi:
    return FirmwareKind::Uefi;

  case WindowsFirmwareType::Bios:
    return FirmwareKind::Bios;

  default:
    return boost::none;
  }
}

// Fallback function for Windows versions that do not implement the
// GetFirmwareType Win32 API
FirmwareKind detectFirmwareTypeFromRegistry() {
  HKEY state_reg_key{nullptr};
  auto error =
      RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                    0,
                    KEY_READ,
                    &state_reg_key);
  if (error == ERROR_SUCCESS) {
    RegCloseKey(state_reg_key);
  }

  return (error == ERROR_SUCCESS) ? FirmwareKind::Uefi : FirmwareKind::Bios;
}

} // namespace

boost::optional<FirmwareKind> getFirmwareKind() {
  auto opt_firmware_kind = queryFirmwareKind();
  if (opt_firmware_kind.has_value()) {
    return opt_firmware_kind.value();
  }

  VLOG(1) << "Attempting to detect the firmware type through the registry";
  return detectFirmwareTypeFromRegistry();
}

} // namespace osquery
