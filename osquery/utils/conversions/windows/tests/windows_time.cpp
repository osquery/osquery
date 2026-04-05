/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <osquery/utils/conversions/windows/windows_time.h>

#include <time.h>
#include <winbase.h>
#include <winnt.h>

namespace osquery {

class ConversionsTests : public testing::Test {};

TEST_F(ConversionsTests, test_filetime_to_unixtime) {
  FILETIME ft;
  time_t curr_time = 1593496251;
  LONGLONG ll = Int32x32To64(curr_time, 10000000) + 116444736000000000;
  ft.dwLowDateTime = static_cast<DWORD>(ll);
  ft.dwHighDateTime = ll >> 32;

  auto converted = filetimeToUnixtime(ft);
  EXPECT_EQ(converted, curr_time);
}

TEST_F(ConversionsTests, test_long_int_to_unixtime) {
  LARGE_INTEGER li;
  li.HighPart = 30821541;
  li.LowPart = 2060031803;

  auto converted = longIntToUnixtime(li);
  EXPECT_EQ(converted, 1593277666);
}

TEST_F(ConversionsTests, test_fattime_to_unixtime) {
  std::string fattime = "24450000";

  auto converted = parseFatTime(fattime);
  EXPECT_EQ(converted, 1409788800);
}

TEST_F(ConversionsTests, test_big_endian_filetime_to_unixtime) {
  // Use a known FILETIME value for Jan 1, 2010 00:00:00 UTC
  // Unix timestamp: 1262304000
  // FILETIME = (1262304000 + 11644473600) * 10000000 = 129067776000000000
  // Hex: 0x01CAAC18BF63C000
  std::string hex_filetime = "01caac18bf63c000";

  auto converted = bigEndianFiletimeToUnixTime(hex_filetime);
  EXPECT_EQ(converted, 1262304000);
}

TEST_F(ConversionsTests, test_big_endian_filetime_invalid) {
  // Too short
  EXPECT_EQ(bigEndianFiletimeToUnixTime("01cb2604"), 0);
  // Too long
  EXPECT_EQ(bigEndianFiletimeToUnixTime("01cb26040e6178d4abcd"), 0);
  // Invalid hex
  EXPECT_EQ(bigEndianFiletimeToUnixTime("01cb26040e6178zz"), 0);
}

TEST_F(ConversionsTests, test_parse_date_us_format) {
  // US format: M/D/YYYY
  auto converted = parseDateToUnixTime("6/25/2010");
  // 2010-06-25 00:00:00 UTC = 1277424000
  EXPECT_EQ(converted, 1277424000);

  // With leading zeros
  converted = parseDateToUnixTime("06/25/2010");
  EXPECT_EQ(converted, 1277424000);
}

TEST_F(ConversionsTests, test_parse_date_iso_format) {
  // ISO format: YYYY-MM-DD
  auto converted = parseDateToUnixTime("2010-06-25");
  EXPECT_EQ(converted, 1277424000);
}

TEST_F(ConversionsTests, test_parse_date_european_format) {
  // European format: D-M-YYYY
  auto converted = parseDateToUnixTime("25-06-2010");
  EXPECT_EQ(converted, 1277424000);
}

TEST_F(ConversionsTests, test_parse_date_invalid) {
  // Empty string
  EXPECT_EQ(parseDateToUnixTime(""), 0);
  // Invalid format
  EXPECT_EQ(parseDateToUnixTime("not-a-date"), 0);
  // Invalid values
  EXPECT_EQ(parseDateToUnixTime("13/32/2010"), 0); // month 13, day 32
  // Year out of range
  EXPECT_EQ(parseDateToUnixTime("6/25/1969"), 0);
}

} // namespace osquery
