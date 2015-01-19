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

extern const std::map<int, std::string> kSMBIOSTypeDescriptions;

void genSMBIOSTables(const uint8_t* tables, size_t length, QueryData& results);
}
}
