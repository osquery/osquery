/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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

} // namespace osquery
