/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/tables.h>

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

/// Get friendly names for each SMBIOS table/section type.
extern const std::map<uint8_t, std::string> kSMBIOSTypeDescriptions;

constexpr uint8_t kSMBIOSTypeBIOS = 0;

/**
 * @brief A generic parser for SMBIOS tables.
 *
 * This generic class does not provide interfaces for finding tables only
 * parsing data once it has been provided.
 */
class SMBIOSParser : private boost::noncopyable {
 public:
  /// Walk the tables and apply a predicate.
  virtual void tables(std::function<void(
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size)>
                          predicate);

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
}
}
