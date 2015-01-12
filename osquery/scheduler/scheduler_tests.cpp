/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#include <gtest/gtest.h>

#include <osquery/scheduler.h>

namespace osquery {

class SchedulerTests : public testing::Test {};

TEST_F(SchedulerTests, test) { EXPECT_EQ(true, true); }

TEST_F(SchedulerTests, test_splay) {
  auto val1 = splayValue(100, 10);
  EXPECT_GE(val1, 90);
  EXPECT_LE(val1, 110);

  auto val2 = splayValue(100, 10);
  EXPECT_GE(val2, 90);
  EXPECT_LE(val2, 110);

  auto val3 = splayValue(10, 0);
  EXPECT_EQ(val3, 10);

  auto val4 = splayValue(100, 1);
  EXPECT_GE(val4, 99);
  EXPECT_LE(val4, 101);

  auto val5 = splayValue(1, 10);
  EXPECT_EQ(val5, 1);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
