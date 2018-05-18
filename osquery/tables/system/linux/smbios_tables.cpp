/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <sstream>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/linux/smbios_utils.h"

#define DECLARE_TABLE_IMPLEMENTATION_smbios_tables
#include <generated/tables/tbl_smbios_tables_defs.hpp>
#define DECLARE_TABLE_IMPLEMENTATION_platform_info
#include <generated/tables/tbl_platform_info_defs.hpp>

namespace osquery {
namespace tables {

#define kLinuxSMBIOSRawAddress_ 0xF0000
#define kLinuxSMBIOSRawLength_ 0x10000

const std::string kLinuxEFISystabPath = "/sys/firmware/efi/systab";
const std::string kLinuxDMISysfsPath = "/sys/firmware/dmi/tables/DMI";

void LinuxSMBIOSParser::readFromAddress(size_t address, size_t length) {
  auto status = osquery::readRawMem(address, length, (void**)&data_);
  if (!status.ok() || data_ == nullptr) {
    return;
  }

  // Search for the SMBIOS/DMI tables magic header string.
  size_t offset;
  for (offset = 0; offset <= (length - sizeof(DMIEntryPoint)); offset += 16) {
    // Could look for "_SM_" for the SMBIOS header, but the DMI header exists
    // in both SMBIOS and the legacy DMI spec.
    if (memcmp(data_ + offset, "_DMI_", 5) == 0) {
      auto dmi_data = (DMIEntryPoint*)(data_ + offset);
      if (discoverTables(dmi_data->tableAddress, dmi_data->tableLength)) {
        break;
      }
    }
  }
}

void LinuxSMBIOSParser::readFromSystab(const std::string& systab) {
  std::string content;
  if (!readFile(kLinuxEFISystabPath, content).ok()) {
    return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    if (line.find("SMBIOS") == 0) {
      auto details = osquery::split(line, "=");
      if (details.size() == 2 && details[1].size() > 2) {
        long long int address;
        safeStrtoll(details[1], 16, address);

        // Be sure not to read past the 0x000F0000 - 0x00100000 range.
        // Otherwise strict /dev/mem access will generate a log line.
        size_t size = 0x100;
        if (address < 0x100000 && (address + size) > 0x100000) {
          // If the address is within the 1M strict /dev/mem boundary, and is
          // within 226 bytes of that boundary, reduce the read size.
          size = 0x100000 - address;
        }
        readFromAddress(address, size);
      }
    }
  }
}

void LinuxSMBIOSParser::readFromSysfs(const std::string& sysfs_dmi) {
  std::string content;
  readFile(sysfs_dmi, content);
  table_data_ = (uint8_t*)malloc(content.size());
  memcpy(table_data_, content.data(), content.size());
  table_size_ = content.size();
}

bool LinuxSMBIOSParser::discoverTables(size_t address, size_t length) {
  // Linux will expose the SMBIOS/DMI entry point structures, which contain
  // a member variable with the DMI tables start address and size.
  // This applies to both the EFI-variable and physical memory search.
  auto status = osquery::readRawMem(address, length, (void**)&table_data_);
  if (!status.ok() || table_data_ == nullptr) {
    return false;
  }

  // The read was successful, save the size and wait for requests to parse.
  table_size_ = length;
  return true;
}

bool LinuxSMBIOSParser::discover() {
  if (osquery::isReadable(kLinuxDMISysfsPath)) {
    VLOG(1) << "Reading SMBIOS from sysfs DMI node";
    readFromSysfs(kLinuxDMISysfsPath);
  } else if (osquery::isReadable(kLinuxEFISystabPath)) {
    VLOG(1) << "Reading SMBIOS from EFI provided memory location";
    readFromSystab(kLinuxEFISystabPath);
  } else {
    readFromAddress(kLinuxSMBIOSRawAddress_, kLinuxSMBIOSRawLength_);
  }
  return valid();
}

QueryData genSMBIOSTables(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](size_t index,
                            const SMBStructHeader* hdr,
                            uint8_t* address,
                            size_t size) {
    genSMBIOSTable(index, hdr, address, size, results);
  }));

  return results;
}

QueryData genMemoryDevices(QueryContext& context) {
  QueryData results;

  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           size_t size) {
    genSMBIOSMemoryDevices(index, hdr, address, size, results);
  });

  return results;
}

QueryData genPlatformInfo(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](size_t index,
                            const SMBStructHeader* hdr,
                            uint8_t* address,
                            size_t size) {
    if (hdr->type != kSMBIOSTypeBIOS || size < 0x12) {
      return;
    }

    Row r;
    // The DMI string data uses offsets (indexes) into a data section that
    // trails the header and structure offsets.
    uint8_t* data = address + hdr->length;
    r["vendor"] = dmiString(data, address, 0x04);
    r["version"] = dmiString(data, address, 0x05);
    r["date"] = dmiString(data, address, 0x08);

    // Firmware load address as a WORD.
    size_t firmware_address = (address[0x07] << 8) + address[0x06];
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0') << firmware_address;
    r["address"] = "0x" + hex_id.str();

    // Firmware size as a count of 64k blocks.
    size_t firmware_size = (address[0x09] + 1) << 6;
    r["size"] = std::to_string(firmware_size * 1024);

    // Minor and major BIOS revisions.
    r["revision"] = std::to_string((size_t)address[0x14]) + "." +
                    std::to_string((size_t)address[0x15]);
    r["volume_size"] = "0";
    r["extra"] = "";
    results.push_back(r);
  }));

  return results;
}
}
} // namespace osquery
