/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/system/time.h>

namespace osquery {

class TimeTests : public testing::Test {};

TEST_F(TimeTests, test_asciitime) {
  const std::time_t epoch = 1491518994;
  const std::string expected = "Thu Apr  6 22:49:54 2017 UTC";

  auto const result = std::gmtime(&epoch);

  EXPECT_EQ(expected, toAsciiTime(result));
}

TEST_F(TimeTests, test_asciitimeutc) {
  const std::time_t epoch = 1491518994;
  const std::string expected = "Thu Apr  6 22:49:54 2017 UTC";

  auto const result = std::localtime(&epoch);

  EXPECT_EQ(expected, toAsciiTimeUTC(result));
}
}
