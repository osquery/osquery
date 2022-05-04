/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/hashing/hashing.h>
#include <osquery/tables/system/smbios_utils.h>

namespace osquery {
namespace tables {

const std::map<uint8_t, std::string> kSMBIOSTypeDescriptions = {
    {0, "BIOS Information"},
    {1, "System Information"},
    {2, "Base Board or Module Information"},
    {3, "System Enclosure or Chassis"},
    {4, "Processor Information"},
    {5, "Memory Controller Information"},
    {6, "Memory Module Information"},
    {7, "Cache Information"},
    {8, "Port Connector Information"},
    {9, "System Slots"},
    {10, "On Board Devices Information"},
    {11, "OEM Strings"},
    {12, "System Configuration Options"},
    {13, "BIOS Language Information"},
    {14, "Group Associations"},
    {15, "System Event Log"},
    {16, "Physical Memory Array"},
    {17, "Memory Device"},
    {18, "32-bit Memory Error Information"},
    {19, "Memory Array Mapped Address"},
    {20, "Memory Device Mapped Address"},
    {21, "Built-in Pointing Device"},
    {22, "Portable Battery"},
    {23, "System Reset"},
    {24, "Hardware Security"},
    {25, "System Power Controls"},
    {26, "Voltage Probe"},
    {27, "Cooling Device"},
    {28, "Temperature Probe"},
    {29, "Electrical Current Probe"},
    {30, "Out-of-Band Remote Access"},
    {31, "Boot Integrity Services"},
    {32, "System Boot Information"},
    {33, "64-bit Memory Error Information"},
    {34, "Management Device"},
    {35, "Management Device Component"},
    {36, "Management Device Threshold Data"},
    {37, "Memory Channel"},
    {38, "IPMI Device Information"},
    {39, "System Power Supply"},
    {40, "Additional Information"},
    {41, "Onboard Devices Extended Info"},
    {126, "Inactive"},
    {127, "End-of-Table"},
    {130, "Memory SPD Data"},
    {131, "OEM Processor Type"},
    {132, "OEM Processor Bus Speed"},
};

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

/**
 * SMBIOS data in the formatted section can BYTE, WORD, DWORD, QWORD lengths.
 * They begin at an offset of the structure examined until the end of
 * length specificed in
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
 **/

/**
 * @brief Returns uint16_t representation of a WORD length field
 *
 *
 * @param address A pointer to the examined structure.
 * @Param offset The field index into address.
 */
inline uint16_t dmiToWord(uint8_t* address, uint8_t offset) {
  return (static_cast<uint16_t>(address[offset + 1]) << 8) |
         static_cast<uint16_t>(address[offset]);
}

/**
 * @brief Returns uint32_t representation of a DWORD length field
 *
 *
 * @param address A pointer to the examined structure.
 * @Param offset The field index into address.
 */
inline uint32_t dmiToDWord(uint8_t* address, uint8_t offset) {
  return (static_cast<uint32_t>(address[offset + 3]) << 24) |
         (static_cast<uint32_t>(address[offset + 2]) << 16) |
         (static_cast<uint32_t>(address[offset + 1]) << 8) |
         static_cast<uint32_t>(address[offset]);
}

/**
 * @brief Returns uint64_t representation of a QWORD length field
 *
 *
 * @param address A pointer to the examined structure.
 * @Param offset The field index into address.
 */
inline uint64_t dmiToQWord(uint8_t* address, uint8_t offset) {
  return (static_cast<uint64_t>(address[offset + 7]) << 56) |
         (static_cast<uint64_t>(address[offset + 6]) << 48) |
         (static_cast<uint64_t>(address[offset + 5]) << 40) |
         (static_cast<uint64_t>(address[offset + 4]) << 32) |
         (static_cast<uint64_t>(address[offset + 3]) << 24) |
         (static_cast<uint64_t>(address[offset + 2]) << 16) |
         (static_cast<uint64_t>(address[offset + 1]) << 8) |
         static_cast<uint64_t>(address[offset]);
}

static inline std::string dmiWordToHexStr(uint8_t* address, uint8_t offset) {
  auto word = dmiToWord(address, offset);
  return toHexStr(word);
}

void SMBIOSParser::tables(std::function<void(size_t index,
                                             const SMBStructHeader* hdr,
                                             uint8_t* address,
                                             uint8_t* textAddrs,
                                             size_t size)> predicate) {
  if (table_data_ == nullptr) {
    return;
  }

  // Keep a pointer to the end of the SMBIOS data for comparison.
  auto tables_end = table_data_ + table_size_;
  auto table = table_data_;

  // Iterate through table structures within SMBIOS data range.
  size_t index = 0;
  while (table + sizeof(SMBStructHeader) <= tables_end) {
    auto header = (const SMBStructHeader*)table;
    if (table + header->length > tables_end) {
      // Invalid header, length must be within SMBIOS data range.
      break;
    }

    if (header->length == 0 && header->handle == 0) {
      // Reached the end (null-padded content).
      break;
    }

    // The SMBIOS structure may have unformatted, double-NULL delimited
    // trailing data, which are usually strings.
    auto next_table = table + header->length;
    for (; next_table + sizeof(SMBStructHeader) <= tables_end; next_table++) {
      if (next_table[0] == 0 && next_table[1] == 0) {
        next_table += 2;
        break;
      }
    }

    auto table_length = next_table - table;
    predicate(index++, header, table, table + header->length, table_length);
    table = next_table;
  }
}

void genSMBIOSTable(size_t index,
                    const SMBStructHeader* hdr,
                    uint8_t* address,
                    size_t size,
                    QueryData& results) {
  Row r;
  // The index is a supplement that keeps track of table order.
  r["number"] = INTEGER(index++);
  r["type"] = INTEGER((unsigned short)hdr->type);
  if (kSMBIOSTypeDescriptions.count(hdr->type) > 0) {
    r["description"] = kSMBIOSTypeDescriptions.at(hdr->type);
  } else {
    r["description"] = "Unknown";
  }

  r["handle"] = BIGINT((unsigned long long)hdr->handle);
  r["header_size"] = INTEGER((unsigned short)hdr->length);

  r["size"] = INTEGER(size);
  r["md5"] = hashFromBuffer(HASH_TYPE_MD5, address, size);
  results.push_back(r);
}

void genSMBIOSMemoryDevices(size_t index,
                            const SMBStructHeader* hdr,
                            uint8_t* address,
                            uint8_t* textAddrs,
                            size_t size,
                            QueryData& results) {
  const size_t maxOffset = 0x26 + 4;
  if (hdr->type != kSMBIOSTypeMemoryDevice || size < maxOffset) {
    return;
  }

  Row r;
  r["handle"] = dmiWordToHexStr(address, 0x02);
  r["array_handle"] = dmiWordToHexStr(address, 0x04);

  auto formFactor = kSMBIOSMemoryFormFactorTable.find(address[0x0E]);
  if (formFactor != kSMBIOSMemoryFormFactorTable.end()) {
    r["form_factor"] = formFactor->second;
  }

  auto memBits = dmiToWord(address, 0x08);
  if (memBits != 0xFFFF) {
    r["total_width"] = INTEGER(memBits);
  }

  memBits = dmiToWord(address, 0x0A);
  if (memBits != 0xFFFF) {
    r["data_width"] = INTEGER(memBits);
  }

  memBits = dmiToWord(address, 0x0C);
  if (memBits != 0xFFFF) {
    r["size"] = (memBits != 0x7FFF) ? INTEGER(memBits)
                                    : INTEGER(dmiToDWord(address, 0x1C));
  }

  if (address[0x0F] != 0xFF) {
    r["set"] = INTEGER(static_cast<int>(address[0x0F]));
  }

  const auto maxlen = size - hdr->length;
  r["device_locator"] = dmiString(textAddrs, address[0x10], maxlen);
  r["bank_locator"] = dmiString(textAddrs, address[0x11], maxlen);

  auto memoryType = kSMBIOSMemoryTypeTable.find(address[0x12]);
  if (memoryType != kSMBIOSMemoryTypeTable.end()) {
    r["memory_type"] = memoryType->second;
  }

  r["memory_type_details"] =
      dmiBitFieldToStr(dmiToWord(address, 0x13), kSMBIOSMemoryDetailsTable);

  auto speed = dmiToWord(address, 0x15);
  if (speed != 0x0000 && speed != 0xFFFF) {
    r["max_speed"] = INTEGER(speed);
  }

  speed = dmiToWord(address, 0x20);
  if (speed != 0x0000 && speed != 0xFFFF) {
    r["configured_clock_speed"] = INTEGER(speed);
  }

  r["manufacturer"] = dmiString(textAddrs, address[0x17], maxlen);
  r["serial_number"] = dmiString(textAddrs, address[0x18], maxlen);
  r["asset_tag"] = dmiString(textAddrs, address[0x19], maxlen);
  r["part_number"] = dmiString(textAddrs, address[0x1A], maxlen);

  auto vt = dmiToWord(address, 0x22);
  if (vt != 0) {
    r["min_voltage"] = INTEGER(vt);
  }

  vt = dmiToWord(address, 0x24);
  if (vt != 0) {
    r["max_voltage"] = INTEGER(vt);
  }

  vt = dmiToWord(address, 0x26);
  if (vt != 0) {
    r["configured_voltage"] = INTEGER(vt);
  }

  results.push_back(std::move(r));
}

void genSMBIOSMemoryArrays(size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           size_t size,
                           QueryData& results) {
  const size_t maxOffset = 0x0F + 8;
  if (hdr->type != kSMBIOSTypeMemoryArray || size < maxOffset) {
    return;
  }

  Row r;
  r["handle"] = dmiWordToHexStr(address, 0x02);

  auto location = kSMBIOSMemoryArrayLocationTable.find(address[0x04]);
  if (location != kSMBIOSMemoryArrayLocationTable.end()) {
    r["location"] = location->second;
  }

  auto use = kSMBIOSMemoryArrayUseTable.find(address[0x05]);
  if (use != kSMBIOSMemoryArrayUseTable.end()) {
    r["use"] = use->second;
  }

  auto errCorrection =
      kSMBIOSMemoryArrayErrorCorrectionTypesTable.find(address[0x06]);
  if (errCorrection != kSMBIOSMemoryArrayErrorCorrectionTypesTable.end()) {
    r["memory_error_correction"] = errCorrection->second;
  }

  auto cap = dmiToDWord(address, 0x07);
  // SMBIOS returns capacity in KB or bytes, but we want a more human
  // friendly GB.
  r["max_capacity"] = (cap >= 0x80000000)
                          ? INTEGER(dmiToQWord(address, 0x0F) / 1073741824)
                          : INTEGER(cap / 1048576);

  auto errHandle = dmiToWord(address, 0x0B);
  if (errHandle != 0xFFFE && errHandle != 0xFFFF) {
    r["memory_error_info_handle"] = toHexStr(errHandle);
  }

  r["number_memory_devices"] = INTEGER(dmiToWord(address, 0x0D));

  results.push_back(std::move(r));
}

void genSMBIOSMemoryArrayMappedAddresses(size_t index,
                                         const SMBStructHeader* hdr,
                                         uint8_t* address,
                                         size_t size,
                                         QueryData& results) {
  const size_t maxOffset = 0x17 + 8;
  if (hdr->type != kSMBIOSTypeMemoryArrayMappedAddress || size < maxOffset) {
    return;
  }

  Row r;
  r["handle"] = dmiWordToHexStr(address, 0x02);

  auto addr = dmiToDWord(address, 0x04);
  if (addr != 0xFFFFFFFF) {
    r["starting_address"] = toHexStr(addr, 8);
    r["ending_address"] = toHexStr(dmiToDWord(address, 0x08), 8);
  } else {
    r["starting_address"] = toHexStr(dmiToQWord(address, 0x0F), 12);
    r["ending_address"] = toHexStr(dmiToQWord(address, 0x17), 12);
  }

  r["memory_array_handle"] = dmiWordToHexStr(address, 0x0C);
  r["partition_width"] = INTEGER(static_cast<int>(address[0x0E]));

  results.push_back(std::move(r));
}

void genSMBIOSMemoryErrorInfo(size_t index,
                              const SMBStructHeader* hdr,
                              uint8_t* address,
                              size_t size,
                              QueryData& results) {
  const size_t maxOffset = 0x13 + 4;
  if (hdr->type != kSMBIOSTypeMemoryErrorInformation || size < maxOffset) {
    return;
  }

  Row r;
  r["handle"] = dmiWordToHexStr(address, 0x02);

  auto errType = kSMBIOSMemoryErrorTypeTable.find(address[0x04]);
  if (errType != kSMBIOSMemoryErrorTypeTable.end()) {
    r["error_type"] = errType->second;
  }

  auto errGran = kSMBIOSMemoryErrorGranularityTable.find(address[0x05]);
  if (errGran != kSMBIOSMemoryErrorGranularityTable.end()) {
    r["error_granularity"] = errGran->second;
  }

  auto errOp = kSMBIOSMemoryErrorOperationTable.find(address[0x06]);
  if (errOp != kSMBIOSMemoryErrorOperationTable.end()) {
    r["error_operation"] = errOp->second;
  }

  auto dword = dmiToDWord(address, 0x07);
  if (dword != 0x00000000) {
    r["vendor_syndrome"] = toHexStr(dword, 8);
  }

  dword = dmiToDWord(address, 0x0B);
  if (dword != 0x80000000) {
    r["memory_array_error_address"] = toHexStr(dword, 8);
  }

  dword = dmiToDWord(address, 0x0F);
  if (dword != 0x80000000) {
    r["device_error_address"] = toHexStr(dword, 8);
  }

  dword = dmiToDWord(address, 0x13);
  if (dword != 0x80000000) {
    r["error_resolution"] = toHexStr(dword, 8);
  }

  results.push_back(std::move(r));
}

void genSMBIOSMemoryDeviceMappedAddresses(size_t index,
                                          const SMBStructHeader* hdr,
                                          uint8_t* address,
                                          size_t size,
                                          QueryData& results) {
  const size_t maxOffset = 0x1B + 8;
  if (hdr->type != kSMBIOSTypeMemoryDeviceMappedAddress || size < maxOffset) {
    return;
  }

  Row r;
  r["handle"] = dmiWordToHexStr(address, 0x02);

  auto addr = dmiToDWord(address, 0x04);
  if (addr != 0xFFFFFFFF) {
    r["starting_address"] = toHexStr(addr, 8);
    r["ending_address"] = toHexStr(dmiToDWord(address, 0x08), 8);
  } else {
    r["starting_address"] = toHexStr(dmiToQWord(address, 0x13), 12);
    r["ending_address"] = toHexStr(dmiToQWord(address, 0x1B), 12);
  }

  r["memory_device_handle"] = dmiWordToHexStr(address, 0x0C);
  r["partition_row_position"] = INTEGER(static_cast<int>(address[0x10]));
  r["interleave_position"] = INTEGER(static_cast<int>(address[0x11]));
  r["interleave_data_depth"] = INTEGER(static_cast<int>(address[0x12]));

  results.push_back(std::move(r));
}

void genSMBIOSOEMStrings(const SMBStructHeader* hdr,
                         uint8_t* address,
                         uint8_t* textAddrs,
                         size_t size,
                         QueryData& results) {
  const size_t maxOffset = 0x04 + 1;
  if (hdr->type != kSMBIOSTypeOEMStrings || size < maxOffset) {
    return;
  }

  auto handle = dmiWordToHexStr(address, 0x02);
  const auto maxlen = size - hdr->length;

  auto numStrings = address[0x04];
  for (auto i = 1; i <= numStrings; i++) {
    results.emplace_back(Row{{"handle", handle},
                             {"number", INTEGER(static_cast<int>(i))},
                             {"value", dmiString(textAddrs, i, maxlen)}});
  }
}

void genSMBIOSProcessor(size_t index,
                        const SMBStructHeader* hdr,
                        uint8_t* address,
                        uint8_t* textAddrs,
                        size_t size,
                        QueryData& results) {
  const size_t maxOffset = 0x2e + 2;
  if (hdr->type != kSMBIOSTypeProcessor || size < maxOffset) {
    return;
  }

  Row r;
  auto maxlen = size - hdr->length;
  r["socket_designation"] = dmiString(textAddrs, address[0x04], maxlen);
  r["model"] = dmiString(textAddrs, address[0x10], maxlen);
  r["manufacturer"] = dmiString(textAddrs, address[0x07], maxlen);
  r["processor_type"] = INTEGER(static_cast<int>(address[0x05]));
  r["cpu_status"] = INTEGER(static_cast<int>(address[0x18]));
  r["number_of_cores"] = INTEGER(static_cast<int>(address[0x23]));
  r["logical_processors"] = INTEGER(static_cast<int>(address[0x25]));
  uint16_t processorChar = dmiToWord(address, 0x26);
  r["address_width"] = (processorChar & (1 << 2)) != 0 ? "64" : "32";
  r["current_clock_speed"] = std::to_string(dmiToWord(address, 0x16));
  r["max_clock_speed"] = std::to_string(dmiToWord(address, 0x14));
  results.push_back(r);
}

std::string dmiString(uint8_t* data, uint8_t index, size_t maxlen) {
  // Guard against faulty SMBIOS data.
  if (index == 0 || maxlen == 0 || data[maxlen - 1] != '\0') {
    return "";
  }

  size_t size = 0;
  auto bp = reinterpret_cast<char*>(data);
  while (index > 1) {
    if (size > maxlen - 1) {
      break;
    }

    while (*bp != 0) {
      if (++size > maxlen - 1) {
        break;
      }
      bp++;
    }
    size++;
    bp++;
    index--;
  }

  if (size > maxlen - 1) {
    // String exceeds text address space, structure seems corrupt.
    return "";
  }

  std::string str(bp);
  // Sometimes vendors leave extraneous spaces on the right side.
  boost::algorithm::trim_right(str);
  return str;
}

std::string dmiBitFieldToStr(size_t bitField,
                             const std::map<uint8_t, std::string>& table) {
  std::string result;

  for (uint8_t i = 0; i < table.size(); i++) {
    if (1 << i & bitField) {
      result = result + table.at(i) + ' ';
    }
  }

  if (!result.empty()) {
    result.pop_back();
  }

  return result;
}

} // namespace tables
} // namespace osquery
