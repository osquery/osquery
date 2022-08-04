/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

typedef struct SMBStructHeader {
  uint8_t type;
  uint8_t length;
  uint16_t handle;
} __attribute__((packed)) SMBStructHeader;

typedef struct DMIEntryPoint {
  uint8_t anchor[5];
  uint8_t checksum;
  uint16_t tableLength;
  uint32_t tableAddress;
  uint16_t structureCount;
  uint8_t bcdRevision;
} __attribute__((packed)) DMIEntryPoint;

/**
 * SMBIOS Lookup for SMBIOS ENUM values as defined in:
 * https://www.dmtf.org/sites/default/files/standards/documents/
 *   DSP0134_3.1.1.pdf
 */

extern const std::map<uint8_t, std::string> kSMBIOSMemoryFormFactorTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryDetailsTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryTypeTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryArrayLocationTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryArrayUseTable;
extern const std::map<uint8_t, std::string>
    kSMBIOSMemoryArrayErrorCorrectionTypesTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryErrorTypeTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryErrorGranularityTable;
extern const std::map<uint8_t, std::string> kSMBIOSMemoryErrorOperationTable;

/// Get friendly names for each SMBIOS table/section type.
extern const std::map<uint8_t, std::string> kSMBIOSTypeDescriptions;

extern const std::map<std::string, std::string>
    kSMBIOSProcessorTypeFriendlyName;

constexpr uint8_t kSMBIOSTypeBIOS = 0;
constexpr uint8_t kSMBIOSTypeSystem = 1;
constexpr uint8_t kSMBIOSTypeBoard = 2;
constexpr uint8_t kSMBIOSTypeProcessor = 4;
constexpr uint8_t kSMBIOSTypeOEMStrings = 11;
constexpr uint8_t kSMBIOSTypeMemoryArray = 16;
constexpr uint8_t kSMBIOSTypeMemoryDevice = 17;
constexpr uint8_t kSMBIOSTypeMemoryErrorInformation = 18;
constexpr uint8_t kSMBIOSTypeMemoryArrayMappedAddress = 19;
constexpr uint8_t kSMBIOSTypeMemoryDeviceMappedAddress = 20;

/**
 * @brief A generic parser for SMBIOS tables.
 *
 * This generic class does not provide interfaces for finding tables only
 * parsing data once it has been provided.
 */
class SMBIOSParser : private boost::noncopyable {
 public:
  /// Walk the tables and apply a predicate.
  virtual void tables(std::function<void(size_t index,
                                         const SMBStructHeader* hdr,
                                         uint8_t* address,
                                         uint8_t* textAddrs,
                                         size_t size)> predicate);

 public:
  virtual ~SMBIOSParser() {}

 protected:
  /// This protected data member is used during table parsing and must be set.
  uint8_t* table_data_{nullptr};

  /// Table size discovered from SMBIOS.
  size_t table_size_{0};
};

/// Helper, cross platform, table row generator.
void genSMBIOSTable(size_t index,
                    const SMBStructHeader* hdr,
                    uint8_t* address,
                    size_t size,
                    QueryData& results);

/// Helper, cross platform, table row generator for memory devices.
void genSMBIOSMemoryDevices(size_t index,
                            const SMBStructHeader* hdr,
                            uint8_t* address,
                            uint8_t* textAddrs,
                            size_t size,
                            QueryData& results);

/// Helper, cross platform, table row generator for memory arrays.
void genSMBIOSMemoryArrays(size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           size_t size,
                           QueryData& results);

/// Helper, cross platform, table row generator for memory mapped addresses.
void genSMBIOSMemoryArrayMappedAddresses(size_t index,
                                         const SMBStructHeader* hdr,
                                         uint8_t* address,
                                         size_t size,
                                         QueryData& results);

/// Helper, cross platform, table row generator for memory error info.
void genSMBIOSMemoryErrorInfo(size_t index,
                              const SMBStructHeader* hdr,
                              uint8_t* address,
                              size_t size,
                              QueryData& results);

/// Helper, cross platform, table row generator for memory device mapped
/// addresses.
void genSMBIOSMemoryDeviceMappedAddresses(size_t index,
                                          const SMBStructHeader* hdr,
                                          uint8_t* address,
                                          size_t size,
                                          QueryData& results);

/// Helper, cross platform, table generator for OEM strings.
void genSMBIOSOEMStrings(const SMBStructHeader* hdr,
                         uint8_t* address,
                         uint8_t* textAddrs,
                         size_t size,
                         QueryData& results);

/// Helper, cross platform, table generator for processor.
void genSMBIOSProcessor(size_t index,
                        const SMBStructHeader* hdr,
                        uint8_t* address,
                        uint8_t* textAddrs,
                        size_t size,
                        QueryData& results);

/**
 * @brief Return a 0-terminated strings from an SMBIOS address and handle.
 *
 * SMBIOS strings are 0-terminated and 'stacked' at the end of the type
 * structure. Each structure identifies (loosely) the type of data within.
 * Using the structure location for where the strings start and the index of
 * target string, the stacked data can be parsed and a string returned.
 *
 * @param data A pointer to the stacked data suffixing the SMBIOS structure.
 * @param index The index of the stacked string.
 * @param maxlen The size of the text region.
 */
std::string dmiString(uint8_t* data, uint8_t index, size_t maxlen);

/**
 * @brief Return std::string representation of a bitfield.
 *
 * SMBIOS fields can contain bit field values where whose values can be resolved
 * with a provided lookup table.
 *
 * @param bitField size_t representation of the bit field.
 * @param table Lookup table for each bit of the bitField.
 */
std::string dmiBitFieldToStr(size_t bitField,
                             const std::map<uint8_t, std::string>& table);

} // namespace tables
} // namespace osquery
