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
#include <fstream>
#include <vector>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/darwin/packages.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genPackageBOM(const std::string& path, QueryData& results);

class PackagesTests : public testing::Test {
 protected:
  void SetUp() override {
    directory_ = fs::temp_directory_path() /
                 fs::unique_path("osquery.packages_tests.%%%%-%%%%");
    ASSERT_TRUE(fs::create_directories(directory_));
  }

  void TearDown() override {
    fs::remove_all(directory_);
  }

  fs::path directory_;
};

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
  putBe32(buf, 8, 1); // version
  putBe32(buf, 12, 0); // numberOfBlocks
  putBe32(buf, 16, 32); // indexOffset -> block table
  putBe32(buf, 20, 0); // indexLength
  putBe32(buf, 24, 52); // varsOffset -> variable table
  putBe32(buf, 28, 0); // varsLength

  // Block table at 32: two pointers.
  putBe32(buf, 32, 2);
  putBe32(buf, 36, 0); // blockPointers[0] null entry
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

// genPackageBOM descends from the Paths tree root to the first leaf by reading
// indices[0] of each non-leaf node. A non-leaf node with count = 0 carries no
// indices, and getPaths only sizes such a block for its 12-byte header, so the
// descent used to read 8 bytes past the block (past the file buffer when the
// block ends at it) and follow that value as the next block index. Here the
// out-of-block bytes decode to a valid leaf: without the count guard the leaf
// is parsed and a row appears; with it the descent stops and nothing is
// emitted.
TEST_F(PackagesTests, test_genpackagebom_stops_on_empty_nonleaf_node) {
  std::vector<char> buf(211, 0);

  // Header.
  std::memcpy(&buf[0], "BOMStore", 8);
  putBe32(buf, 8, 1); // version
  putBe32(buf, 12, 0); // numberOfBlocks
  putBe32(buf, 16, 32); // indexOffset -> block table
  putBe32(buf, 20, 0); // indexLength
  putBe32(buf, 24, 92); // varsOffset -> variable table
  putBe32(buf, 28, 0); // varsLength

  // Block table at 32: count + 7 pointers (addr, length).
  putBe32(buf, 32, 7);
  putBe32(buf, 36, 0);
  putBe32(buf, 40, 0); // [0] null
  putBe32(buf, 44, 106);
  putBe32(buf, 48, 21); // [1] tree
  putBe32(buf, 52, 127);
  putBe32(buf, 56, 12); // [2] empty non-leaf node
  putBe32(buf, 60, 147);
  putBe32(buf, 64, 20); // [3] leaf
  putBe32(buf, 68, 167);
  putBe32(buf, 72, 8); // [4] BOMPathInfo1
  putBe32(buf, 76, 175);
  putBe32(buf, 80, 31); // [5] BOMPathInfo2
  putBe32(buf, 84, 206);
  putBe32(buf, 88, 5); // [6] BOMFile

  // Variable table at 92: one BOMVar{index -> tree, length} + name "Paths".
  putBe32(buf, 92, 1);
  putBe32(buf, 96, 1);
  buf[100] = 5;
  std::memcpy(&buf[101], "Paths", 5);

  // Tree block at 106: child -> block 2 (the empty non-leaf node).
  std::memcpy(&buf[106], "tree", 4);
  putBe32(buf, 110, 1); // version
  putBe32(buf, 114, 2); // child
  putBe32(buf, 118, 512); // blockSize
  putBe32(buf, 122, 0); // pathCount

  // Empty non-leaf node at 127 (12 bytes): isLeaf = 0, count = 0.
  putBe16(buf, 127, 0);
  putBe16(buf, 129, 0);
  putBe32(buf, 131, 0); // forward
  putBe32(buf, 135, 0); // backward

  // The 8 bytes right after the node's declared length decode to indices[0]
  // of a non-empty node: index0 -> block 3 (leaf), index1 -> block 6.
  putBe32(buf, 139, 3);
  putBe32(buf, 143, 6);

  // Leaf node at 147: isLeaf = 1, count = 1, indices[0] = {4, 6}.
  putBe16(buf, 147, 1);
  putBe16(buf, 149, 1);
  putBe32(buf, 151, 0); // forward
  putBe32(buf, 155, 0); // backward
  putBe32(buf, 159, 4); // indices[0].index0 -> BOMPathInfo1
  putBe32(buf, 163, 6); // indices[0].index1 -> BOMFile

  // BOMPathInfo1 at 167: id, index -> block 5 (BOMPathInfo2).
  putBe32(buf, 167, 1);
  putBe32(buf, 171, 5);

  // BOMPathInfo2 at 175 (31 bytes, left zeroed).

  // BOMFile at 206: parent = 0, name = "X" (file_size 5 > sizeof(BOMFile)).
  putBe32(buf, 206, 0);
  buf[210] = 'X';

  BOM bom(buf.data(), buf.size());
  ASSERT_TRUE(bom.isValid());

  auto bom_path = (directory_ / "empty_node.bom").string();
  {
    std::ofstream fout(bom_path, std::ios::binary);
    fout.write(buf.data(), buf.size());
  }

  QueryData results;
  genPackageBOM(bom_path, results);
  EXPECT_TRUE(results.empty());

  // Point the empty node's forward at itself. If the node were handed to
  // genBOMPaths, its zero count would skip entry processing and getPaths
  // would keep returning the same node, so the query would never finish.
  putBe32(buf, 131, 2);
  {
    std::ofstream fout(bom_path, std::ios::binary | std::ios::trunc);
    fout.write(buf.data(), buf.size());
  }

  results.clear();
  genPackageBOM(bom_path, results);
  EXPECT_TRUE(results.empty());
}
} // namespace tables
} // namespace osquery
