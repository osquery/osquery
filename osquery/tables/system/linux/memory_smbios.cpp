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
} // namespace tables
} // namespace osquery
