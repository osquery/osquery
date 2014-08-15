// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/scheduler.h"

#include <gtest/gtest.h>

using namespace osquery::scheduler;

class SchedulerTests : public testing::Test {};

TEST_F(SchedulerTests, test) { EXPECT_EQ(true, true); }

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
