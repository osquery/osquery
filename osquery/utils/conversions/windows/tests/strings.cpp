/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fcntl.h>
#include <io.h>

#include <string>

#include <gtest/gtest.h>

#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

class ConversionsTests : public testing::Test {
 public:
  ConversionsTests() {}

  void SetUp() {
    auto ret = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (ret != S_OK) {
      CoUninitialize();
    }
  }

  void TearDown() {
    CoUninitialize();
  }
};

TEST_F(ConversionsTests, test_string_to_wstring) {
  std::string narrow_string{"The quick brown fox jumps over the lazy dog"};
  auto wide_string = stringToWstring(narrow_string);
  std::wstring expected{L"The quick brown fox jumps over the lazy dog"};
  EXPECT_EQ(wide_string, expected);
}

TEST_F(ConversionsTests, test_cim_datetime_to_unixtime) {
  std::string cim_date_time{"20190724000000.000000-000"};
  auto unixtime = cimDatetimeToUnixtime(cim_date_time);
  EXPECT_EQ(unixtime, 1563926400);
}

TEST_F(ConversionsTests, test_wstring_to_string) {
  std::wstring wide_string{L"The quick brown fox jumps over the lazy dog"};
  auto narrow_string = wstringToString(wide_string);
  std::string expected{"The quick brown fox jumps over the lazy dog"};
  EXPECT_EQ(narrow_string, expected);
}

TEST_F(ConversionsTests, test_string_to_wstring_extended) {
  std::string narrow_string{"fr\xc3\xb8tz-jorn"};
  auto wide_string = stringToWstring(narrow_string);
  std::wstring expected{L"fr\x00f8tz-jorn"};
  EXPECT_EQ(wide_string, expected);
}

TEST_F(ConversionsTests, test_wstring_to_string_extended) {
  std::wstring wide_string{L"fr\x00f8tz-jorn"};
  auto narrow_string = wstringToString(wide_string);
  std::string expected{"fr\xc3\xb8tz-jorn"};
  EXPECT_EQ(narrow_string, expected);
}

TEST_F(ConversionsTests, test_swapendianiess) {
  std::string little_endian{"IJGHEFCDAB"};
  auto swapendian = swapEndianess(little_endian);
  std::string expected{"ABCDEFGHIJ"};
  EXPECT_EQ(swapendian, expected);
}

TEST_F(ConversionsTests, test_string_to_wstring_embedded_nulls) {
  /* A std::string is supposed to contain the entire data,
     therefore supporting embedded nulls.
     No additional scan of the string to find a null terminator
     will be done for the conversion. */
  std::string narrow_string = "123\0\0\0123";
  auto wide_string = stringToWstring(narrow_string);

  std::wstring expected = L"123\0\0\0123";
  EXPECT_EQ(wide_string, expected);

  // Using a char* does the scan instead
  expected = L"123";
  wide_string = stringToWstring(narrow_string.c_str());
  EXPECT_EQ(wide_string, expected);
}

TEST_F(ConversionsTests, test_wstring_to_string_embedded_nulls) {
  /* A std::wstring is supposed to contain the entire data,
     therefore supporting embedded nulls.
     No additional scan of the string to find a null terminator
     will be done for the conversion. */
  std::wstring wide_string = L"123\0\0\0123";
  auto narrow_string = wstringToString(wide_string);

  std::string expected = "123\0\0\0123";
  EXPECT_EQ(narrow_string, expected);

  // Using a char* does the scan instead
  expected = "123";
  narrow_string = wstringToString(wide_string.c_str());
  EXPECT_EQ(narrow_string, expected);
}

TEST_F(ConversionsTests, test_wstring_to_string_max_conversion_factor) {
  // Surrogate pairs
  std::wstring wide_string = L"\U0001F600\U0001F601";
  auto narrow_string = wstringToString(wide_string);

  std::string expected = u8"\U0001F600\U0001F601";

  EXPECT_EQ(narrow_string, expected);

  // U0800 to U0FFF
  wide_string = L"\u0800\u0801";
  narrow_string = wstringToString(wide_string);

  expected = u8"\u0800\u0801";
  EXPECT_EQ(narrow_string, expected);
}

} // namespace osquery
