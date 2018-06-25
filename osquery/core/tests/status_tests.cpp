/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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

TEST_F(StatusTests, test_default_constructor) {
  auto s = Status{};
  EXPECT_TRUE(s.ok());
}

TEST_F(StatusTests, test_success_code) {
  auto s = Status(Status::success_code);
  EXPECT_TRUE(s.ok());
}

TEST_F(StatusTests, test_success) {
  auto s = Status::success();
  EXPECT_TRUE(s.ok());
}

TEST_F(StatusTests, test_failure_single_arg) {
  auto s = Status::failure("Some proper error message.");
  EXPECT_EQ(s.toString(), "Some proper error message.");
  EXPECT_FALSE(s.ok());
}

TEST_F(StatusTests, test_failure_double_arg) {
  auto s = Status::failure(105, "One more proper error message!");
  EXPECT_EQ(s.toString(), "One more proper error message!");
  EXPECT_FALSE(s.ok());
}

TEST_F(StatusTests, test_failure_with_success_code) {
#ifndef NDEBUG
  ASSERT_DEATH(Status::failure(Status::success_code, "message"),
               "Using Status::failure to create Status object with a "
               "Status::success_code");
#endif
}
}
