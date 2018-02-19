/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

#include "osquery/tables/system/linux/smbios_utils.h"

namespace osquery {
namespace tables {

const std::map<uint8_t, std::string> kSMBIOSMemoryFormFactorTable = {
    {0x01, "Other"},
    {0x02, "Unknown"},
    {0x03, "SIMM"},
    {0x04, "SIP"},
    {0x05, "Chip"},
    {0x06, "DIP"},
    {0x07, "ZIP"},
    {0x08, "Proprietary Card"},
    {0x09, "DIMM"},
    {0x0A, "TSOP"},
    {0x0B, "Row of chips"},
    {0x0C, "RIMM"},
    {0x0D, "SODIMM"},
    {0x0E, "SRIMM"},
    {0x0F, "FB-DIMM"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryDetailsTable = {
    {0, "Reserved"},
    {1, "Other"},
    {2, "Unknown"},
    {3, "Fast-paged"},
    {4, "Static column"},
    {5, "Pseudo-static"},
    {6, "RAMBUS"},
    {7, "Synchronous"},
    {8, "CMOS"},
    {9, "EDO"},
    {10, "Window DRAM"},
    {11, "Cache DRAM"},
    {12, "Non-volatile"},
    {13, "Registered (Buffered)"},
    {14, "Unbuffered (Unregistered)"},
    {15, "LRDIMM"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryTypeTable = {
    {0x01, "Other"},    {0x02, "Unknown"},      {0x03, "DRAM"},
    {0x04, "EDRAM"},    {0x05, "VRAM"},         {0x06, "SRAM"},
    {0x07, "RAM"},      {0x08, "ROM"},          {0x09, "FLASH"},
    {0x0A, "EEPROM"},   {0x0B, "FEPROM"},       {0x0C, "EPROM"},
    {0x0D, "CDRAM"},    {0x0E, "3DRAM"},        {0x0F, "SDRAM"},
    {0x10, "SGRAM"},    {0x11, "RDRAM"},        {0x12, "DDR"},
    {0x13, "DDR2"},     {0x14, "DDR2 FB-DIMM"}, {0x15, "RESERVED"},
    {0x16, "RESERVED"}, {0x17, "RESERVED"},     {0x18, "DDR3"},
    {0x19, "FBD2"},     {0x1A, "DDR4"},         {0x1B, "LPDDR"},
    {0x1C, "LPDDR2"},   {0x1D, "LPDDR3"},       {0x1E, "LPDDR4"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryArrayLocationTable = {
    {0x01, "Other"},
    {0x02, "Unknown"},
    {0x03, "System board or motherboard"},
    {0x04, "ISA add-on card"},
    {0x05, "EISA add-on card"},
    {0x06, "PCI add-on card"},
    {0x07, "MCA add-on card"},
    {0x08, "PCMCIA add-on card"},
    {0x09, "Proprietary add-on card"},
    {0x0A, "NuBus"},
    {0xA0, "PC-98/C20 add-on card"},
    {0xA1, "PC-98/C24 add-on card"},
    {0xA2, "PC-98/E add-on card"},
    {0xA3, "PC-98/Local bus add-on card"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryArrayUseTable = {
    {0x01, "Other"},
    {0x02, "Unknown"},
    {0x03, "System memory"},
    {0x04, "Video memory"},
    {0x05, "Flash memory"},
    {0x06, "Non-volatile RAM"},
    {0x07, "Cache memory"},
};

const std::map<uint8_t, std::string>
    kSMBIOSMemoryArrayErrorCorrectionTypesTable = {
        {0x01, "Other"},
        {0x02, "Unknown"},
        {0x03, "none"},
        {0x04, "Parity"},
        {0x05, "Single-bit ECC"},
        {0x06, "Multi-bit ECC"},
        {0x07, "CRC"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryErrorTypeTable = {
    {0x01, "Other"},
    {0x02, "Unknown"},
    {0x03, "OK"},
    {0x04, "Bad read"},
    {0x05, "Parity error"},
    {0x06, "Single-bit error"},
    {0x07, "Double-bit error"},
    {0x08, "Multi-bit error"},
    {0x09, "Nibble error"},
    {0x0A, "Checksum error"},
    {0x0B, "CRC error"},
    {0x0C, "Corrected single-bit error"},
    {0x0D, "Corrected error"},
    {0x0E, "Uncorrectable error"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryErrorGranularityTable = {
    {0x01, "Other"},
    {0x02, "Unknown"},
    {0x03, "Device level"},
    {0x04, "Memory partition level"},
};

const std::map<uint8_t, std::string> kSMBIOSMemoryErrorOperationTable = {
    {0x01, "Other"},
    {0x02, "Unknown"},
    {0x03, "Read"},
    {0x04, "Write"},
    {0x05, "Partial write"},
};

template <class T>
static inline std::string toHexStr(T num, int width = 4) {
  std::stringstream ss;
  ss << std::hex << std::setw(width) << std::setfill('0') << num;
  return "0x" + ss.str();
}

static inline std::string dmiWordToHexStr(uint8_t* address, uint8_t offset) {
  auto word = linuxDmiToWord(address, offset);
  return toHexStr(word);
}

uint16_t linuxDmiToWord(uint8_t* address, uint8_t offset) {
  return (static_cast<uint16_t>(address[offset + 1]) << 8) |
         static_cast<uint16_t>(address[offset]);
}

uint32_t linuxDmiToDword(uint8_t* address, uint8_t offset) {
  return (static_cast<uint32_t>(address[offset + 3]) << 24) |
         (static_cast<uint32_t>(address[offset + 2]) << 16) |
         (static_cast<uint32_t>(address[offset + 1]) << 8) |
         static_cast<uint32_t>(address[offset]);
}

uint64_t linuxDmiToQword(uint8_t* address, uint8_t offset) {
  return (static_cast<uint64_t>(address[offset + 7]) << 56) |
         (static_cast<uint64_t>(address[offset + 6]) << 48) |
         (static_cast<uint64_t>(address[offset + 5]) << 40) |
         (static_cast<uint64_t>(address[offset + 4]) << 32) |
         (static_cast<uint64_t>(address[offset + 3]) << 24) |
         (static_cast<uint64_t>(address[offset + 2]) << 16) |
         (static_cast<uint64_t>(address[offset + 1]) << 8) |
         static_cast<uint64_t>(address[offset]);
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
    if (hdr->type != kSMBIOSTypeMemoryDevice || size < 0x12) {
      return;
    }

    Row r;
    r["handle"] = dmiWordToHexStr(address, 0x02);
    r["array_handle"] = dmiWordToHexStr(address, 0x04);

    if (kSMBIOSMemoryFormFactorTable.find(address[0x0E]) !=
        kSMBIOSMemoryFormFactorTable.end()) {
      r["form_factor"] = kSMBIOSMemoryFormFactorTable.at(address[0x0E]);
    }

    auto memBits = linuxDmiToWord(address, 0x08);
    if (memBits != 0xFFFF) {
      r["total_width"] = INTEGER(memBits);
    }

    memBits = linuxDmiToWord(address, 0x0A);
    if (memBits != 0xFFFF) {
      r["data_width"] = INTEGER(memBits);
    }

    memBits = linuxDmiToWord(address, 0x0C);
    if (memBits != 0xFFFF) {
      r["size"] = (memBits != 0x7FFF) ? INTEGER(memBits)
                                      : INTEGER(linuxDmiToDword(address, 0x1C));
    }

    if (address[0x0F] != 0xFF) {
      r["set"] = INTEGER(static_cast<int>(address[0x0F]));
    }

    uint8_t* data = address + hdr->length;
    r["device_locator"] = dmiString(data, address, 0x10);
    r["bank_locator"] = dmiString(data, address, 0x11);

    if (kSMBIOSMemoryTypeTable.find(address[0x12]) !=
        kSMBIOSMemoryTypeTable.end()) {
      r["memory_type"] = kSMBIOSMemoryTypeTable.at(address[0x12]);
    }

    r["memory_type_details"] = dmiBitFieldToStr(linuxDmiToWord(address, 0x13),
                                                kSMBIOSMemoryDetailsTable);

    auto speed = linuxDmiToWord(address, 0x15);
    if (speed != 0x0000 && speed != 0xFFFF) {
      r["max_speed"] = INTEGER(speed);
    }

    speed = linuxDmiToWord(address, 0x20);
    if (speed != 0x0000 && speed != 0xFFFF) {
      r["configured_clock_speed"] = INTEGER(speed);
    }

    r["manufacturer"] = dmiString(data, address, 0x17);
    r["serial_number"] = dmiString(data, address, 0x18);
    r["asset_tag"] = dmiString(data, address, 0x19);
    r["part_number"] = dmiString(data, address, 0x1A);

    auto vt = linuxDmiToWord(address, 0x22);
    if (vt != 0) {
      r["min_voltage"] = INTEGER(vt);
    }

    vt = linuxDmiToWord(address, 0x24);
    if (vt != 0) {
      r["max_voltage"] = INTEGER(vt);
    }

    vt = linuxDmiToWord(address, 0x26);
    if (vt != 0) {
      r["configured_voltage"] = INTEGER(vt);
    }

    results.push_back(std::move(r));
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
                           size_t size) {
    if (hdr->type != kSMBIOSTypeMemoryArray || size < 0x12) {
      return;
    }

    Row r;
    r["handle"] = dmiWordToHexStr(address, 0x02);

    if (kSMBIOSMemoryArrayLocationTable.find(address[0x04]) !=
        kSMBIOSMemoryArrayLocationTable.end()) {
      r["location"] = kSMBIOSMemoryArrayLocationTable.at(address[0x04]);
    }

    if (kSMBIOSMemoryArrayUseTable.find(address[0x05]) !=
        kSMBIOSMemoryArrayUseTable.end()) {
      r["use"] = kSMBIOSMemoryArrayUseTable.at(address[0x05]);
    }

    if (kSMBIOSMemoryArrayErrorCorrectionTypesTable.find(address[0x06]) !=
        kSMBIOSMemoryArrayErrorCorrectionTypesTable.end()) {
      r["memory_error_correction"] =
          kSMBIOSMemoryArrayErrorCorrectionTypesTable.at(address[0x06]);
    }

    auto cap = linuxDmiToDword(address, 0x07);
    // SMBIOS returns capacity in KB or bytes, but we want a more human
    // friendly GB.
    r["max_capacity"] =
        (cap >= 0x80000000)
            ? INTEGER(linuxDmiToQword(address, 0x0F) / 1073741824)
            : INTEGER(cap / 1048576);

    auto errHandle = linuxDmiToWord(address, 0x0B);
    if (errHandle != 0xFFFE) {
      r["memory_error_info_handle"] =
          (errHandle == 0xFFFF) ? "No Errors" : toHexStr(errHandle);
    }

    r["number_memory_devices"] = INTEGER(linuxDmiToWord(address, 0x0D));

    results.push_back(std::move(r));
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
                           size_t size) {
    if (hdr->type != kSMBIOSTypeMemoryArrayMappedAddress || size < 0x12) {
      return;
    }

    Row r;
    r["handle"] = dmiWordToHexStr(address, 0x02);

    auto addr = linuxDmiToDword(address, 0x04);
    if (addr != 0xFFFFFFFF) {
      r["starting_address"] = toHexStr(addr, 8);
      r["ending_address"] = toHexStr(linuxDmiToDword(address, 0x08), 8);
    } else {
      r["starting_address"] = toHexStr(linuxDmiToQword(address, 0x0F), 12);
      r["ending_address"] = toHexStr(linuxDmiToQword(address, 0x17), 12);
    }

    r["memory_array_handle"] = dmiWordToHexStr(address, 0x0C);
    r["partition_width"] = INTEGER(static_cast<int>(address[0x0E]));

    results.push_back(std::move(r));
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
                           size_t size) {
    if (hdr->type != kSMBIOSTypeMemoryErrorInformation || size < 0x12) {
      return;
    }

    Row r;
    r["handle"] = dmiWordToHexStr(address, 0x02);

    if (kSMBIOSMemoryErrorTypeTable.find(address[0x04]) !=
        kSMBIOSMemoryErrorTypeTable.end()) {
      r["error_type"] = kSMBIOSMemoryErrorTypeTable.at(address[0x04]);
    }

    if (kSMBIOSMemoryErrorGranularityTable.find(address[0x05]) !=
        kSMBIOSMemoryErrorGranularityTable.end()) {
      r["error_granularity"] =
          kSMBIOSMemoryErrorGranularityTable.at(address[0x05]);
    }

    if (kSMBIOSMemoryErrorOperationTable.find(address[0x06]) !=
        kSMBIOSMemoryErrorOperationTable.end()) {
      r["error_operation"] = kSMBIOSMemoryErrorOperationTable.at(address[0x06]);
    }

    auto dword = linuxDmiToDword(address, 0x07);
    if (dword != 0x00000000) {
      r["vendor_syndrome"] = toHexStr(dword, 8);
    }

    dword = linuxDmiToDword(address, 0x0B);
    if (dword != 0x80000000) {
      r["memory_array_error_address"] = toHexStr(dword, 8);
    }

    dword = linuxDmiToDword(address, 0x0F);
    if (dword != 0x80000000) {
      r["device_error_address"] = toHexStr(dword, 8);
    }

    dword = linuxDmiToDword(address, 0x13);
    if (dword != 0x80000000) {
      r["error_resolution"] = toHexStr(dword, 8);
    }
    results.push_back(std::move(r));
  });

  return results;
}
} // namespace tables
} // namespace osquery
