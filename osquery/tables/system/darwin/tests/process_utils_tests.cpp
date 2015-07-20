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

#include <osquery/filesystem.h>

pid_t getpid(void);

namespace osquery {

namespace tables {
bool isPidRunning(pid_t);
}

class ProcessUtilsTest : public testing::Test {};

TEST_F(ProcessUtilsTest, test_self_is_running) {
  EXPECT_TRUE(tables::isPidRunning(getpid()));
}

TEST_F(ProcessUtilsTest, test_absurd_is_not_running) {
  EXPECT_FALSE(tables::isPidRunning(-1));
}
}
