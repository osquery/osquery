/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>
#include <osquery/error.h>

enum class TestError { SomeError = 1, AnotherError = 2 };

GTEST_TEST(ErrorTest, initialization) {
  auto error = osquery::Error<TestError>(TestError::SomeError, "TestMessage");
  EXPECT_EQ(error.getUnderlyingError(), nullptr);
  EXPECT_TRUE(error == TestError::SomeError);
  EXPECT_EQ(error.getShortMessage(), "TestError 1");
  EXPECT_EQ(error.getFullMessage(), "TestError 1 (TestMessage)");
}

GTEST_TEST(ErrorTest, exception) {
  auto exception = std::logic_error("Logic error exception");
  auto error = osquery::Error<TestError>(
      TestError::AnotherError, exception, "TestMessage");
  EXPECT_NE(error.getUnderlyingError(), nullptr);
  EXPECT_TRUE(error == TestError::AnotherError);
  EXPECT_EQ(error.getShortMessage(), "TestError 2");
  EXPECT_EQ(error.getFullMessage(), "TestError 2 (TestMessage)");
}

GTEST_TEST(ErrorTest, recursive) {
  auto orignalError = std::make_shared<osquery::Error<TestError>>(
      TestError::SomeError, "SuperTestMessage");
  auto error = osquery::Error<TestError>(
      TestError::AnotherError, "TestMessage", orignalError);
  EXPECT_NE(error.getUnderlyingError(), nullptr);
  EXPECT_EQ(error.getShortMessageRecursive(), "TestError 2 <- TestError 1");
  EXPECT_EQ(error.getFullMessageRecursive(),
            "TestError 2 (TestMessage) <- TestError 1 (SuperTestMessage)");
}
