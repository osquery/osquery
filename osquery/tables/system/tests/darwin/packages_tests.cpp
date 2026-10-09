/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <arpa/inet.h>

#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/darwin/packages.h>

namespace osquery {
namespace tables {

class PackagesTests : public testing::Test {};

TEST_F(PackagesTests, test_bom_parsing) {
  std::string content;
  auto test_bom_path = (getTestConfigDirectory() / "test_bom.bom").string();
  if (!readFile(test_bom_path, content).ok()) {
    return;
  }

  // Create a BOM representation.
  BOM bom(content.c_str(), content.size());
  ASSERT_TRUE(bom.isValid());

  size_t offset = 0;
  auto var = bom.getVariable(&offset);
  ASSERT_FALSE(nullptr == var);
}

namespace {

void putBe32(std::vector<char>& buf, size_t offset, uint32_t value) {
  uint32_t be = htonl(value);
  std::memcpy(&buf[offset], &be, sizeof(be));
}

void putBe16(std::vector<char>& buf, size_t offset, uint16_t value) {
  uint16_t be = htons(value);
  std::memcpy(&buf[offset], &be, sizeof(be));
}

} // namespace

// A BOMPaths block must be large enough to hold its header plus the number
// of indices it declares. A block whose length equals count*sizeof(index)
// but leaves no room for the header previously let the declared indices
// reach past the block (and, when the block ends at the buffer, past the
// allocation).
TEST_F(PackagesTests, test_bom_getpaths_rejects_truncated_block) {
  std::vector<char> buf(72, 0);

  // Header.
  std::memcpy(&buf[0], "BOMStore", 8);
  putBe32(buf, 8, 1);   // version
  putBe32(buf, 12, 0);  // numberOfBlocks
  putBe32(buf, 16, 32); // indexOffset -> block table
  putBe32(buf, 20, 0);  // indexLength
  putBe32(buf, 24, 52); // varsOffset -> variable table
  putBe32(buf, 28, 0);  // varsLength

  // Block table at 32: two pointers.
  putBe32(buf, 32, 2);
  putBe32(buf, 36, 0);  // blockPointers[0] null entry
  putBe32(buf, 40, 0);
  putBe32(buf, 44, 56); // blockPointers[1] address
  putBe32(buf, 48, 16); // blockPointers[1] length

  // Variable table at 52: empty.
  putBe32(buf, 52, 0);

  // Crafted BOMPaths block at 56, 16 bytes, ending at the buffer end.
  // It declares count=2 (needs sizeof(BOMPaths) + 2*sizeof(BOMPathIndices)
  // bytes) but only 16 bytes are present.
  putBe16(buf, 56, 0); // isLeaf
  putBe16(buf, 58, 2); // count
  putBe32(buf, 60, 0); // forward
  putBe32(buf, 64, 0); // backward

  BOM bom(buf.data(), buf.size());
  ASSERT_TRUE(bom.isValid());

  // getPointer applies ntohl to the index, so pass it in network order.
  EXPECT_EQ(nullptr, bom.getPaths(htonl(1)));
}
} // namespace tables
} // namespace osquery
