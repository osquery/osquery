/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/status/status.h>

#include <boost/algorithm/string.hpp>

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
  auto s = Status(Status::kSuccessCode);
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
  ASSERT_DEATH(Status::failure(Status::kSuccessCode, "message"),
               "Using 'failure' to create Status object with a kSuccessCode");
#endif
}

namespace {

enum class TestError {
  Semantic = 1,
};

bool stringContains(const std::string& where, const std::string& what) {
  return boost::contains(where, what);
};

} // namespace

TEST_F(StatusTests, test_expected_to_status_failure) {
  const auto expected = Expected<std::string, TestError>(
      TestError::Semantic, "The ultimate failure reason");
  auto s = to<Status>(expected);
  EXPECT_FALSE(s.ok());
  EXPECT_PRED2(stringContains, s.toString(), "The ultimate failure reason");
}

TEST_F(StatusTests, test_expected_to_status_success) {
  const auto expected =
      Expected<std::string, TestError>("This is not a failure");
  auto s = to<Status>(expected);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s, Status::success());
}
}
