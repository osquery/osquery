/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdint>
#include <string>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/events/darwin/diskarbitration.h>
#include <osquery/filesystem/filesystem.h>

namespace fs = boost::filesystem;

namespace osquery {

namespace {

void writeBigEndian32(std::string& buffer, size_t offset, uint32_t value) {
  buffer[offset] = static_cast<char>((value >> 24) & 0xff);
  buffer[offset + 1] = static_cast<char>((value >> 16) & 0xff);
  buffer[offset + 2] = static_cast<char>((value >> 8) & 0xff);
  buffer[offset + 3] = static_cast<char>(value & 0xff);
}

/// Build a disk image made only of a koly trailer with a CRC32 master
/// checksum, declaring the given checksum size.
std::string makeUdifImage(uint32_t checksum_size) {
  std::string trailer(512, '\0');
  trailer.replace(0, 4, "koly");
  // Master checksum type (CRC32), size, and the checksum itself.
  writeBigEndian32(trailer, 352, 2);
  writeBigEndian32(trailer, 356, checksum_size);
  writeBigEndian32(trailer, 360, 0x12345678);
  // Image variant and sector count follow the 128 byte checksum field.
  writeBigEndian32(trailer, 488, 1);
  writeBigEndian32(trailer, 496, 0xabcdef01);
  return trailer;
}

} // namespace

class DiskArbitrationTests : public testing::Test {
 protected:
  void SetUp() override {
    image_path_ = fs::temp_directory_path() /
                  fs::unique_path("osquery.diskarbitration.%%%%.%%%%.dmg");
  }

  void TearDown() override {
    boost::system::error_code ec;
    fs::remove(image_path_, ec);
  }

  bool writeImage(uint32_t checksum_size) {
    boost::system::error_code ec;
    fs::remove(image_path_, ec);
    return writeTextFile(image_path_, makeUdifImage(checksum_size)).ok();
  }

  fs::path image_path_;
};

TEST_F(DiskArbitrationTests, test_extract_udif_checksum) {
  // A CRC32 master checksum, with the size hdiutil writes (32).
  ASSERT_TRUE(writeImage(32));
  EXPECT_EQ(
      DiskArbitrationEventPublisher::extractUdifChecksum(image_path_.string()),
      "12345678");

  // A size larger than the checksum field must not read past the field.
  ASSERT_TRUE(writeImage(4096));
  EXPECT_EQ(
      DiskArbitrationEventPublisher::extractUdifChecksum(image_path_.string()),
      "12345678");
}

} // namespace osquery
