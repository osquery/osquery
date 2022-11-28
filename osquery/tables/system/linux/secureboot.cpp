/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>
#include <osquery/utils/info/firmware.h>

namespace osquery::tables {

namespace {

// Linux has 2 places efivars can be accessed:
//   /sys/firmware/efi/efivars -- Single file, world readable
//   /sys/firmware/efi/vars    -- Split into attributes and data, only root
//   readable
//
// There's not much documentation about the provenance of these two
// interfaces. While the `vars` directory is more usable (having a
// split data from attributes), the benefit of not requiring root
// outweighs that.
//
// Note that the efivars may not have been mounted
const std::string kEfiDirectory{"/sys/firmware/efi"};
const std::string kEfiVarsDirectory{kEfiDirectory + "/efivars"};

void readBoolEfiVar(Row& row,
                    std::string column_name,
                    std::string guid,
                    std::string name) {
  const std::string efivarPath = kEfiVarsDirectory + "/" + name + '-' + guid;

  // The first 4 bytes of efivars are attribute data, we don't need
  // that data here, so we can just ignore it. The 5th byte is a
  // boolean representation.
  std::string efiData;
  if (!readFile(efivarPath, efiData, 5).ok()) {
    // failure to read _probably_ means the kernel doesn't support EFI
    // vars. This is not uncommon.
    return;
  }

  if (efiData.length() != 5) {
    TLOG << "Under read on efivar file : " << efivarPath;
    return;
  }

  auto val = (int)(unsigned char)(efiData.back());

  switch (val) {
  case 0:
    row.emplace(column_name, "0");
    break;
  case 1:
    row.emplace(column_name, "1");
    break;
  default:
    TLOG << "Unknown value in efivar(" << efivarPath << "). Got: " << val;
    row.emplace(column_name, "-1");
    break;
  }

  return;
}

} // namespace

QueryData genSecureBoot(QueryContext& context) {
  auto opt_firmware_kind = getFirmwareKind();
  if (!opt_firmware_kind.has_value()) {
    LOG(ERROR) << "secureboot: Failed to determine the firmware type";
    return {};
  }

  const auto& firmware_kind = opt_firmware_kind.value();
  if (firmware_kind != FirmwareKind::Uefi) {
    VLOG(1) << "secureboot: Secure boot is only supported on UEFI firmware";
    return {};
  }

  // There's a kernel rate limit on non-root reads to the EFI
  // filesystem of 100 reads per second. We could consider adding a
  // sleep, as a means to a rate limit (this is what the efivar tool
  // does), but this seems unlikely to be an issue in normal osquery
  // use. So we do nothing, aside from note it here.
  Row r;
  readBoolEfiVar(r, "secure_boot", kEFIBootGUID, kEFISecureBootName);
  readBoolEfiVar(r, "setup_mode", kEFIBootGUID, kEFISetupModeName);

  return {std::move(r)};
}

} // namespace osquery::tables
