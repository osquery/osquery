/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/versioning/semantic.h>

namespace osquery {
namespace {

class SemanticVersionTests : public testing::Test {};

TEST_F(SemanticVersionTests, pass) {
  auto exp = tryTo<SemanticVersion>("1.6.9");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 1u);
  EXPECT_EQ(exp.get().minor, 6u);
  EXPECT_EQ(exp.get().patches, 9u);
}

TEST_F(SemanticVersionTests, pass_2) {
  auto exp = tryTo<SemanticVersion>("7.25.999");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 7u);
  EXPECT_EQ(exp.get().minor, 25u);
  EXPECT_EQ(exp.get().patches, 999u);
}

TEST_F(SemanticVersionTests, pass_suffix) {
  auto exp = tryTo<SemanticVersion>("0.8.2_50_302b_1");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 0u);
  EXPECT_EQ(exp.get().minor, 8u);
  EXPECT_EQ(exp.get().patches, 2u);
}

TEST_F(SemanticVersionTests, fail_major) {
  auto exp = tryTo<SemanticVersion>("a4.5.9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_minor) {
  auto exp = tryTo<SemanticVersion>("9.f1.9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_patches) {
  auto exp = tryTo<SemanticVersion>("1.6.c9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_separator_minus) {
  auto exp = tryTo<SemanticVersion>("1-6-9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_separator_colon) {
  auto exp = tryTo<SemanticVersion>("1:6:9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_empty) {
  auto exp = tryTo<SemanticVersion>("");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_one_digit) {
  auto exp = tryTo<SemanticVersion>("818");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_two_digits) {
  auto exp = tryTo<SemanticVersion>("66.66");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

} // namespace
} // namespace osquery
