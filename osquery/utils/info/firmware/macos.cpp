/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_map>

#include <osquery/utils/info/firmware.h>

#include <boost/filesystem.hpp>

#include <IOKit/IOKitLib.h>

namespace osquery {

boost::optional<FirmwareKind> getFirmwareKind() {
  // clang-format off
  static const std::unordered_map<FirmwareKind, std::string> kFirmwareToRegistryPath{
    { FirmwareKind::Uefi, kIODeviceTreePlane ":/efi" },
    { FirmwareKind::iBoot, kIODeviceTreePlane ":/chosen/iBoot" },
    { FirmwareKind::OpenFirmware, kIODeviceTreePlane ":/openprom" },
  };
  // clang-format on

  mach_port_t master_port{};
  if (IOMasterPort(MACH_PORT_NULL, &master_port) != 0) {
    return boost::none;
  }

  boost::optional<FirmwareKind> opt_detected_firmware_type;

  for (const auto& p : kFirmwareToRegistryPath) {
    const auto& firmware_type = p.first;
    const auto& registry_path = p.second;

    auto registry_entry =
        IORegistryEntryFromPath(master_port, registry_path.c_str());

    if (registry_entry != MACH_PORT_NULL) {
      IOObjectRelease(registry_entry);
      return firmware_type;
    }
  }

  return boost::none;
}

} // namespace osquery
