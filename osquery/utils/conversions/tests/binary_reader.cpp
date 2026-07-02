/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/conversions/binary_reader.h>

#include <string>

namespace osquery {

class BinaryReaderTests : public testing::Test {};

TEST_F(BinaryReaderTests, size_and_raw) {
  std::string s("\x01\x02\x03", 3);
  BinaryReader r(s);
  EXPECT_EQ(r.size(), 3u);
  EXPECT_EQ(r.raw().size(), 3u);
}

TEST_F(BinaryReaderTests, bytes_in_bounds) {
  std::string s("ABCDEF", 6);
  BinaryReader r(s);
  auto v = r.bytes(1, 3);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "BCD");
}

TEST_F(BinaryReaderTests, bytes_out_of_bounds_returns_nullopt) {
  std::string s("ABC", 3);
  BinaryReader r(s);
  EXPECT_FALSE(r.bytes(1, 3).has_value());
  EXPECT_FALSE(r.bytes(4, 0).has_value());
}

TEST_F(BinaryReaderTests, bytes_zero_length_at_end_returns_empty) {
  std::string s("ABC", 3);
  BinaryReader r(s);
  auto v = r.bytes(3, 0);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "");
}

TEST_F(BinaryReaderTests, bytes_from_in_bounds_returns_suffix) {
  std::string s("ABCDEF", 6);
  BinaryReader r(s);
  auto v = r.bytes_from(2);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "CDEF");
}

TEST_F(BinaryReaderTests, bytes_from_at_size_returns_empty) {
  std::string s("ABC", 3);
  BinaryReader r(s);
  auto v = r.bytes_from(3);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "");
}

TEST_F(BinaryReaderTests, bytes_from_past_size_returns_nullopt) {
  std::string s("ABC", 3);
  BinaryReader r(s);
  EXPECT_FALSE(r.bytes_from(4).has_value());
}

TEST_F(BinaryReaderTests, u8_reads_one_byte) {
  std::string s("\x1F\x80", 2);
  BinaryReader r(s);
  EXPECT_EQ(r.u8(0), std::uint8_t{0x1F});
  EXPECT_EQ(r.u8(1), std::uint8_t{0x80});
  EXPECT_FALSE(r.u8(2).has_value());
}

TEST_F(BinaryReaderTests, u16_le_reads_little_endian) {
  std::string s("\x34\x12", 2);
  BinaryReader r(s);
  EXPECT_EQ(r.u16_le(0), std::uint16_t{0x1234});
  EXPECT_FALSE(r.u16_le(1).has_value());
}

TEST_F(BinaryReaderTests, u32_le_reads_little_endian) {
  std::string s("\x78\x56\x34\x12", 4);
  BinaryReader r(s);
  EXPECT_EQ(r.u32_le(0), std::uint32_t{0x12345678});
  EXPECT_FALSE(r.u32_le(1).has_value());
  EXPECT_FALSE(r.u32_le(2).has_value());
}

TEST_F(BinaryReaderTests, find_locates_pattern) {
  std::string s("ABABXY", 6);
  BinaryReader r(s);
  EXPECT_EQ(r.find("AB"), 0u);
  EXPECT_EQ(r.find("AB", 1), 2u);
  EXPECT_EQ(r.find("ZZ"), BinaryReader::npos);
}

// GHSA-h348-cc3h-grw6: 3-byte payload that crashed the old parser at
// substr(8, 32) inside rootFolderItem. The reader equivalent must
// short-circuit on the bounds check rather than throwing.
TEST_F(BinaryReaderTests, ghsa_h348_payload_short_read_returns_nullopt) {
  std::string s("\x00\x00\x1F", 3);
  BinaryReader r(s);
  EXPECT_FALSE(r.bytes(4, 16).has_value());
}

TEST_F(BinaryReaderTests, strip_null_bytes_ascii_in_utf16_le) {
  // "Hi" in UTF-16LE: H, 0, i, 0 — high bytes are dropped.
  std::string s("H\0i\0", 4);
  EXPECT_EQ(stripNullBytes(s), "Hi");
}

TEST_F(BinaryReaderTests, strip_null_bytes_keeps_non_null) {
  // Legacy "erase_all '00' + unhex" drops literal null bytes only.
  // Non-ASCII UTF-16 code units survive as raw garbage — this matches
  // the (incorrect-but-shipped) legacy behavior.
  std::string s("H\0\xA6\x03i\0", 6);
  EXPECT_EQ(stripNullBytes(s), std::string("H\xA6\x03i", 4));
}

TEST_F(BinaryReaderTests, strip_null_bytes_empty_input) {
  EXPECT_EQ(stripNullBytes(""), "");
}

TEST_F(BinaryReaderTests, strip_null_bytes_all_nulls_returns_empty) {
  std::string s("\0\0\0", 3);
  EXPECT_EQ(stripNullBytes(s), "");
}

} // namespace osquery
