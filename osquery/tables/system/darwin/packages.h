/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <vector>
#include <map>
#include <string>

namespace osquery {
namespace tables {

// Structure details based on work from Joseph Coffland, Julian Devlin
struct BOMHeader {
  // Always "BOMStore"
  char magic[8];
  // Always 1
  uint32_t version;
  // Number of non-null entries in BOMBlockTable
  uint32_t numberOfBlocks;
  uint32_t indexOffset;
  uint32_t indexLength;
  uint32_t varsOffset;
  uint32_t varsLength;
} __attribute__((packed));

struct BOMPointer {
  uint32_t address;
  uint32_t length;
} __attribute__((packed));

struct BOMBlockTable {
  // See header for number of non-null blocks
  uint32_t count;
  // First entry must always be a null entry
  BOMPointer blockPointers[];
} __attribute__((packed));

struct BOMTree {
  // Always "tree"
  char tree[4];
  // Always 1
  uint32_t version;
  // Index for BOMPaths
  uint32_t child;
  // Always 4096
  uint32_t blockSize;
  // Total number of paths in all leaves combined
  uint32_t pathCount;
  uint8_t unknown3;
} __attribute__((packed));

struct BOMVar {
  uint32_t index;
  uint8_t length;
  char name[];
} __attribute__((packed));

struct BOMVars {
  uint32_t count;
  BOMVar list[];
} __attribute__((packed));

struct BOMPathIndices {
  // for leaf: points to BOMPathInfo1, for branch points to BOMPaths
  uint32_t index0;
  // always points to BOMFile
  uint32_t index1;
} __attribute__((packed));

struct BOMPaths {
  uint16_t isLeaf;
  uint16_t count;
  uint32_t forward;
  uint32_t backward;
  BOMPathIndices indices[];
} __attribute__((packed));

struct BOMPathInfo2 {
  uint8_t type;
  uint8_t unknown0;
  uint16_t architecture;
  uint16_t mode;
  uint32_t user;
  uint32_t group;
  uint32_t modtime;
  uint32_t size;
  uint8_t unknown1;
  union {
    uint32_t checksum;
    uint32_t devType;
  };
  uint32_t linkNameLength;
  char linkName[];
} __attribute__((packed));

struct BOMPathInfo1 {
  uint32_t id;
  // Pointer to BOMPathInfo2
  uint32_t index;
} __attribute__((packed));

struct BOMFile {
  // Parent BOMPathInfo1->id
  uint32_t parent;
  char name[];
} __attribute__((packed));

class BOM {
 public:
  BOM(const char* data, size_t size);

  /// Helper to check if the header parsing completed.
  bool isValid() const { return valid_; }

  /// Lookup a BOM pointer and optionally, its size.
  const char* getPointer(int index, size_t* length = nullptr) const;

  const BOMPaths* getPaths(int index) const;

  const BOMVar* getVariable(size_t* offset) const;

 private:
  const char* data_;
  size_t size_;
  bool valid_;

 private:
  size_t vars_offset_{0};
  size_t table_offset_{0};

 public:
  const BOMHeader* Header{nullptr};
  const BOMBlockTable* Table{nullptr};
  const BOMVars* Vars{nullptr};
};
}
}
