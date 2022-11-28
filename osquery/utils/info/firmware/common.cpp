

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

namespace osquery {

const std::string& getFirmwareKindDescription(
    const FirmwareKind& firmware_kind) {
  static const std::unordered_map<FirmwareKind, std::string>
      kFirmwareKindNameMap{
          {FirmwareKind::Bios, "bios"},
          {FirmwareKind::Uefi, "uefi"},
          {FirmwareKind::iBoot, "iboot"},
          {FirmwareKind::OpenFirmware, "openfirmware"},
      };

  auto it = kFirmwareKindNameMap.find(firmware_kind);
  if (it != kFirmwareKindNameMap.end()) {
    return it->second;
  }

  static const std::string kUnknownFirmwareKind{"unknown"};
  return kUnknownFirmwareKind;
}

} // namespace osquery
