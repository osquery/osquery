/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mach-o/dyld.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>
#include <boost/make_unique.hpp>

#include "osquery/tests/test_util.h"
#include <osquery/config/tests/test_utils.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genSignatureForFile(const std::string& path,
                         bool hashResources,
                         QueryData& results);

// Get the full, real path to the unsigned test executable (only works on
// Darwin).
std::string getUnsignedExecutablePath() {
  return (getTestConfigDirectory() / "unsigned_test").string();
}

class SignatureTest : public testing::Test {
 protected:
  void SetUp() {
    tempFile = kTestWorkingDirectory + "darwin-signature";
  }

  void TearDown() {
    // End the event loops, and join on the threads.
    fs::remove_all(tempFile);
  }

 protected:
  std::string tempFile;
};

/*
 * Ensures that the signature for a signed binary is correct.
 *
 * We use `/bin/ls` as the test binary, since it should be present "everywhere".
 */
TEST_F(SignatureTest, test_get_valid_signature) {
  std::string path = "/bin/ls";

  Row expected = {{"path", path},
                  {"signed", "1"},
                  {"identifier", "com.apple.ls"},
                  {"authority", "Software Signing"}};

  for (bool hash_resources : {true, false}) {
    QueryData results;
    genSignatureForFile(path, hash_resources, results);

    const auto& first_row = results.front();

    for (const auto& column : expected) {
      const auto& actual_value = first_row.at(column.first);
      const auto& expected_value = column.second;

      EXPECT_EQ(expected_value, actual_value)
          << " for column named " << column.first;
    }

    EXPECT_EQ(first_row.at("hash_resources"), INTEGER(hash_resources));

    // Could check the team identifier but it is flaky on some distros.
    // ASSERT_TRUE(results.front()["team_identifier"].length() > 0);
    ASSERT_TRUE(first_row.at("cdhash").length() > 0);
  }
}

/*
 * Ensures that the results for an unsigned binary are correct.
 *
 * We use the currently-running binary as the 'unsigned binary', rather than
 * relying on a particular binary to be present.
 */
TEST_F(SignatureTest, test_get_unsigned) {
  std::string path = getUnsignedExecutablePath();

  QueryData results;
  genSignatureForFile(path, true, results);

  Row expected = {{"path", path},
                  {"hash_resources", "1"},
                  {"signed", "0"},
                  {"identifier", ""},
                  {"cdhash", ""},
                  {"team_identifier", ""},
                  {"authority", ""}};

  for (const auto& column : expected) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }
}

/**
 * Invalidate a universal binary's signature by modifying one byte in each
 * architecture section.
 */
void invalidateUniversalBinarySignature(std::vector<uint8_t>& binary) {
  uint32_t sliceCount;
  uint32_t offset;
  uint32_t sliceSize;

  // offset 4 = uint32 number of architecture slices
  sliceCount = CFSwapInt32BigToHost(*(uint32_t*)&binary[4]);

  // offset 8 = uint32 start of first slice header
  uint32_t sliceHeader = 8;
  for (uint32_t i = 0; i < sliceCount; ++i) {
    // slice header offset 8 = offset to slice data
    offset = CFSwapInt32BigToHost(*(uint32_t*)&binary[sliceHeader + 8]);
    // slice header offset 12 = size of slice data, in bytes
    sliceSize = CFSwapInt32BigToHost(*(uint32_t*)&binary[sliceHeader + 12]);

    // slice headers are 20 bytes in length, go to the next slice header
    sliceHeader += 20;
    if (offset && sliceSize) {
      // Modify the middle most byte in the architecture slice
      uint32_t target = offset + (sliceSize / 2);
      binary[target] = ~binary[target];
    }
  }
}

/**
 * Invalidate a Mach-O binary by modifying one byte in the middle of the file.
 */
void invalidateMachOBinarySignature(std::vector<uint8_t>& binary) {
  uint32_t offset = binary.size() / 2;
  binary[offset] = ~binary[offset];
}

/*
 * Ensures that the results for a signed but invalid binary are correct.
 *
 * This test is a bit of a hack - we copy an existing signed binary (/bin/ls,
 * like above), and then modify one byte in each architecture slice. This should
 * ensure that it differs from whatever the original byte was, and should thus
 * invalidate the signature for the slice.
 */
TEST_F(SignatureTest, test_get_invalid_signature) {
  std::string originalPath = "/bin/ls";
  std::string newPath = tempFile;

  // Create a buffer to hold the entire file.
  std::vector<uint8_t> binary;
  binary.resize(fs::file_size(originalPath));
  ASSERT_TRUE(binary.size() > 0);

  // Open existing file
  FILE* f = fopen(originalPath.c_str(), "rb");
  ASSERT_TRUE(f != nullptr);

  // Read it to memory
  auto nread = fread(&binary[0], sizeof(uint8_t), binary.size(), f);
  fclose(f);
  ASSERT_EQ(nread, binary.size());

  uint32_t magic = *(uint32_t*)&binary[0];
  if (magic == 0xCAFEBABE || magic == 0xBEBAFECA) {
    invalidateUniversalBinarySignature(binary);
  } else {
    invalidateMachOBinarySignature(binary);
  }

  // Write it back to a file.
  f = fopen(newPath.c_str(), "wb");
  ASSERT_TRUE(f != nullptr);
  fwrite(&binary[0], sizeof(uint8_t), binary.size(), f);
  fclose(f);

  // Get the signature of this new file.
  QueryData results;
  genSignatureForFile(newPath, true, results);

  Row expected = {{"path", newPath},
                  {"hash_resources", "1"},
                  {"signed", "0"},
                  {"identifier", "com.apple.ls"},
                  {"authority", "Software Signing"}};

  for (const auto& column : expected) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }
  ASSERT_TRUE(results.front().count("team_identifier") > 0);
  ASSERT_TRUE(results.front()["cdhash"].length() > 0);
}
}
}
