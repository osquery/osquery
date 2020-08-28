/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <sstream>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/smbios_utils.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

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
        long long int address = tryTo<long long>(details[1], 16).takeOr(0ll);

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
  if (table_data_ != nullptr) {
    memcpy(table_data_, content.data(), content.size());
    table_size_ = content.size();
  } else {
    table_size_ = 0;
  }
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
                            uint8_t* textAddrs,
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
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryDevices(index, hdr, address, textAddrs, size, results);
  });

  return results;
}

QueryData genMemoryArrays(QueryContext& context) {
  QueryData results;

  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryArrays(index, hdr, address, size, results);
  });

  return results;
}

QueryData genMemoryArrayMappedAddresses(QueryContext& context) {
  QueryData results;

  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryArrayMappedAddresses(index, hdr, address, size, results);
  });

  return results;
}

QueryData genMemoryErrorInfo(QueryContext& context) {
  QueryData results;

  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryErrorInfo(index, hdr, address, size, results);
  });

  return results;
}

QueryData genMemoryDeviceMappedAddresses(QueryContext& context) {
  QueryData results;

  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryDeviceMappedAddresses(index, hdr, address, size, results);
  });

  return results;
}

QueryData genOEMStrings(QueryContext& context) {
  QueryData results;

  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSOEMStrings(hdr, address, textAddrs, size, results);
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
                            uint8_t* textAddrs,
                            size_t size) {
    const size_t maxOffset = 0x15;
    if (hdr->type != kSMBIOSTypeBIOS || size < maxOffset) {
      return;
    }

    Row r;

    const auto maxlen = size - hdr->length;
    r["vendor"] = dmiString(textAddrs, address[0x04], maxlen);
    r["version"] = dmiString(textAddrs, address[0x05], maxlen);
    r["date"] = dmiString(textAddrs, address[0x08], maxlen);

    // Firmware load address as a WORD.
    size_t firmware_address = (address[0x07] << 8) + address[0x06];
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0') << firmware_address;
    r["address"] = "0x" + hex_id.str();

    // Firmware size as a count of 64k blocks.
    size_t firmware_size = (address[0x09] + 1) << 6;
    r["size"] = std::to_string(firmware_size * 1024);

    // Minor and major BIOS revisions.
    r["revision"] = std::to_string(static_cast<size_t>(address[0x14])) + "." +
                    std::to_string(static_cast<size_t>(address[0x15]));
    r["volume_size"] = "0";
    r["extra"] = "";
    results.push_back(r);
  }));

  return results;
}
} // namespace tables
} // namespace osquery
