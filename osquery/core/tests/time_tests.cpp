/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/system.h>

#include "osquery/core/utils.h"
#include "osquery/tests/test_util.h"

namespace osquery {

class TimeTests : public testing::Test {};

TEST_F(TimeTests, test_asciitime) {
  const size_t epoch = 1491518994;
  const std::string expected = "Thu Apr  6 22:49:54 2017 UTC";

  struct tm result;
  gmtime_r((time_t*)&epoch, &result);

  EXPECT_EQ(expected, toAsciiTime(&result));
}

TEST_F(TimeTests, test_asciitimeutc) {
  const size_t epoch = 1491518994;
  const std::string expected = "Thu Apr  6 22:49:54 2017 UTC";

  struct tm result;
  localtime_r((time_t*)&epoch, &result);

  EXPECT_EQ(expected, toAsciiTimeUTC(&result));
}
}
