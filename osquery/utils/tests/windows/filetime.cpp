/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <string>
namespace osquery {
class FiletimeTests : public testing::Test {};

TEST_F(FiletimeTests, test_filetime) {
  std::string time = "00c0bdd640c6cf01";
  long long unix_time = littleEndianToUnixTime(time);
  ASSERT_TRUE(unix_time == 1409616000);
}
} // namespace osquery