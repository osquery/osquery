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

  auto shortMsg = error.getShortMessageRecursive();
  EXPECT_NE(std::string::npos, shortMsg.find("TestError 1"));

  auto fullMsg = error.getFullMessageRecursive();
  EXPECT_NE(std::string::npos, fullMsg.find("TestError 1"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestMessage"));
}

GTEST_TEST(ErrorTest, recursive) {
  auto orignalError = std::make_shared<osquery::Error<TestError>>(
      TestError::SomeError, "SuperTestMessage");
  auto error = osquery::Error<TestError>(
      TestError::AnotherError, "TestMessage", orignalError);
  EXPECT_NE(error.getUnderlyingError(), nullptr);

  auto shortMsg = error.getShortMessageRecursive();
  EXPECT_NE(std::string::npos, shortMsg.find("TestError 1"));
  EXPECT_NE(std::string::npos, shortMsg.find("TestError 2"));

  auto fullMsg = error.getFullMessageRecursive();
  EXPECT_NE(std::string::npos, fullMsg.find("TestError 1"));
  EXPECT_NE(std::string::npos, fullMsg.find("SuperTestMessage"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestError 2"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestMessage"));
}
