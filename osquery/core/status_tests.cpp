/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/status.h>

#include <gtest/gtest.h>

namespace osquery {

class StatusTests : public testing::Test {};

TEST_F(StatusTests, test_constructor) {
  auto s = Status(5, "message");
  EXPECT_EQ(s.getCode(), 5);
  EXPECT_EQ(s.getMessage(), "message");
}

TEST_F(StatusTests, test_constructor_2) {
  Status s;
  EXPECT_EQ(s.getCode(), 0);
  EXPECT_EQ(s.getMessage(), "OK");
}

TEST_F(StatusTests, test_ok) {
  auto s1 = Status(5, "message");
  EXPECT_FALSE(s1.ok());
  auto s2 = Status(0, "message");
  EXPECT_TRUE(s2.ok());
}

TEST_F(StatusTests, test_to_string) {
  auto s = Status(0, "foobar");
  EXPECT_EQ(s.toString(), "foobar");
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
