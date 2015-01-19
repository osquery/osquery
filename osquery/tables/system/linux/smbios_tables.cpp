/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/smbios_utils.h"

namespace osquery {
namespace tables {

#define kLinuxSMBIOSRawAddress_ 0xF0000
#define kLinuxSMBIOSRawLength_ 0x10000

const std::string kLinuxEFISystabPath = "/sys/firmware/efi/systab";
const std::string kLinuxLegacyEFISystabPath = "/proc/efi/systab";

void genSMBIOSFromDMI(size_t base, size_t length, QueryData& results) {
  // Linux will expose the SMBIOS/DMI entry point structures, which contain
  // a member variable with the DMI tables start address and size.
  // This applies to both the EFI-variable and physical memory search.
  uint8_t* data;
  auto status = osquery::readRawMem(base, length, (void**)&data);
  if (!status.ok()) {
    VLOG(1) << "Could not read DMI tables memory";
    return;
  }

  // Attempt to parse tables from allocated data.
  genSMBIOSTables(data, length, results);
  free(data);
}

void genEFISystabTables(QueryData& results) {
  // Not yet supported.
  return;
}

void genRawSMBIOSTables(QueryData& results) {
  uint8_t* data;
  auto status = osquery::readRawMem(
      kLinuxSMBIOSRawAddress_, kLinuxSMBIOSRawLength_, (void**)&data);
  if (!status.ok()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return;
  }

  // Search for the SMBIOS/DMI tables magic header string.
  size_t offset;
  for (offset = 0; offset <= 0xFFF0; offset += 16) {
    // Could look for "_SM_" for the SMBIOS header, but the DMI header exists
    // in both SMBIOS and the legacy DMI spec.
    if (memcmp(data + offset, "_DMI_", 5) == 0) {
      auto dmi_data = (DMIEntryPoint*)(data + offset);
      genSMBIOSFromDMI(dmi_data->tableAddress, dmi_data->tableLength, results);
    }
  }

  free(data);
}

QueryData genSMBIOSTables(QueryContext& context) {
  QueryData results;

  if (osquery::isReadable(kLinuxEFISystabPath).ok() ||
      osquery::isReadable(kLinuxLegacyEFISystabPath).ok()) {
    genEFISystabTables(results);
  } else {
    genRawSMBIOSTables(results);
  }

  return results;
}
}
}
