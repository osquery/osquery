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

#include <boost/algorithm/string/trim.hpp>

#include "osquery/tables/system/linux/smbios_utils.h"

namespace osquery {
namespace tables {

const std::map<uint8_t, std::string> kFormFactorTable = {
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

const std::map<uint8_t, std::string> kMemoryDetailsTable = {
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

const std::map<uint8_t, std::string> kMemoryTypeTable = {
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

size_t dmiBytesToSizet(uint8_t* address, uint8_t offset, size_t bytes = 2) {
  size_t result{0};

  for (size_t i = 0; i < bytes; i++) {
    result |= address[offset + i] << (i * 8);
  }

  return result;
}

static inline std::string dmiWordToHexString(uint8_t* address, uint8_t offset) {
  auto word = dmiBytesToSizet(address, offset);
  std::stringstream ss;
  ss << std::hex << word;
  return "0x" + ss.str();
}

static inline std::string dmiBitFieldToStr(
    size_t bitField, const std::map<uint8_t, std::string>& table) {
  std::stringstream ss;

  for (uint8_t i = 0; i < table.size(); i++) {
    if (1 << i & bitField) {
      ss << table.at(i) + " ";
    }
  }

  auto result = ss.str();
  boost::algorithm::trim(result);
  return result;
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
    r["handle"] = dmiWordToHexString(address, 0x02);
    r["array_handle"] = dmiWordToHexString(address, 0x04);

    if (kFormFactorTable.count(address[0x0E]) > 0) {
      r["form_factor"] = kFormFactorTable.at(address[0x0E]);
    }

    auto memBits = dmiBytesToSizet(address, 0x08);
    if (memBits != 0xFFFF) {
      r["total_width"] = INTEGER(memBits);
    }

    memBits = dmiBytesToSizet(address, 0x0A);
    if (memBits != 0xFFFF) {
      r["data_width"] = INTEGER(memBits);
    }

    memBits = dmiBytesToSizet(address, 0x0C);
    if (memBits != 0xFFFF) {
      if (memBits != 0x7FFF) {
        r["size"] = INTEGER(memBits);
      } else {
        r["size"] = INTEGER(dmiBytesToSizet(address, 0x1C, 4));
      }
    }

    if (address[0x0F] != 0xFF) {
      r["set"] = INTEGER(static_cast<int>(address[0x0F]));
    }

    uint8_t* data = address + hdr->length;
    r["device_locator"] = dmiString(data, address, 0x10);
    r["bank_locator"] = dmiString(data, address, 0x11);

    if (kMemoryTypeTable.count(address[0x12]) > 0) {
      r["memory_type"] = kMemoryTypeTable.at(address[0x12]);
    }

    r["memory_type_details"] =
        dmiBitFieldToStr(dmiBytesToSizet(address, 0x13), kMemoryDetailsTable);

    auto speed = dmiBytesToSizet(address, 0x15);
    if (speed != 0x0000 && speed != 0xFFFF) {
      r["max_speed"] = INTEGER(speed);
    }

    speed = dmiBytesToSizet(address, 0x20);
    if (speed != 0x0000 && speed != 0xFFFF) {
      r["configured_clock_speed"] = INTEGER(speed);
    }

    r["manufacturer"] = dmiString(data, address, 0x17);
    r["serial_number"] = dmiString(data, address, 0x18);
    r["asset_tag"] = dmiString(data, address, 0x19);
    r["part_number"] = dmiString(data, address, 0x1A);

    auto vt = dmiBytesToSizet(address, 0x22);
    if (vt != 0) {
      r["min_voltage"] = INTEGER(vt);
    }

    vt = dmiBytesToSizet(address, 0x24);
    if (vt != 0) {
      r["max_voltage"] = INTEGER(vt);
    }

    vt = dmiBytesToSizet(address, 0x26);
    if (vt != 0) {
      r["configured_voltage"] = INTEGER(vt);
    }

    results.push_back(r);
  });

  return results;
}
} // namespace tables
} // namespace osquery
