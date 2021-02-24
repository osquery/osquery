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
  std::string narrowString{"The quick brown fox jumps over the lazy dog"};
  auto wideString = stringToWstring(narrowString.c_str());
  std::wstring expected{L"The quick brown fox jumps over the lazy dog"};
  EXPECT_EQ(wideString, expected);
}

TEST_F(ConversionsTests, test_cim_datetime_to_unixtime) {
  std::string cimDateTime{"20190724000000.000000-000"};
  auto unixtime = cimDatetimeToUnixtime(cimDateTime);
  EXPECT_EQ(unixtime, 1563926400);
}

TEST_F(ConversionsTests, test_wstring_to_string) {
  std::wstring wideString{L"The quick brown fox jumps over the lazy dog"};
  auto narrowString = wstringToString(wideString.c_str());
  std::string expected{"The quick brown fox jumps over the lazy dog"};
  EXPECT_EQ(narrowString, expected);
}

TEST_F(ConversionsTests, test_string_to_wstring_extended) {
  std::string narrowString{"fr\xc3\xb8tz-jorn"};
  auto wideString = stringToWstring(narrowString.c_str());
  std::wstring expected{L"fr\x00f8tz-jorn"};
  EXPECT_EQ(wideString, expected);
}

TEST_F(ConversionsTests, test_wstring_to_string_extended) {
  std::wstring wideString{L"fr\x00f8tz-jorn"};
  auto narrowString = wstringToString(wideString.c_str());
  std::string expected{"fr\xc3\xb8tz-jorn"};
  EXPECT_EQ(narrowString, expected);
}

TEST_F(ConversionsTests, test_swapendianiess) {
  std::string little_endian{"IJGHEFCDAB"};
  auto swapendian = swapEndianess(little_endian);
  std::string expected{"ABCDEFGHIJ"};
  EXPECT_EQ(swapendian, expected);
}

} // namespace osquery
