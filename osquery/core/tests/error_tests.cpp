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

#include <boost/algorithm/string.hpp>

#include <osquery/error.h>

enum class TestError {
  SomeError = 1,
  AnotherError = 2,
};

GTEST_TEST(ErrorTest, initialization) {
  auto error = osquery::Error<TestError>(TestError::SomeError, "TestMessage");
  EXPECT_FALSE(error.hasUnderlyingError());
  EXPECT_TRUE(error == TestError::SomeError);

  auto shortMsg = error.getShortMessageRecursive();
  EXPECT_NE(std::string::npos, shortMsg.find("TestError 1"));

  auto fullMsg = error.getFullMessageRecursive();
  EXPECT_NE(std::string::npos, fullMsg.find("TestError 1"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestMessage"));
}

GTEST_TEST(ErrorTest, recursive) {
  auto orignalError = std::make_unique<osquery::Error<TestError>>(
      TestError::SomeError, "SuperTestMessage");
  auto error = osquery::Error<TestError>(
      TestError::AnotherError, "TestMessage", std::move(orignalError));
  EXPECT_TRUE(error.hasUnderlyingError());

  auto shortMsg = error.getShortMessageRecursive();
  EXPECT_NE(std::string::npos, shortMsg.find("TestError 1"));
  EXPECT_NE(std::string::npos, shortMsg.find("TestError 2"));

  auto fullMsg = error.getFullMessageRecursive();
  EXPECT_NE(std::string::npos, fullMsg.find("TestError 1"));
  EXPECT_NE(std::string::npos, fullMsg.find("SuperTestMessage"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestError 2"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestMessage"));
}

bool stringContains(const std::string& where, const std::string& what) {
  return boost::contains(where, what);
};

GTEST_TEST(ErrorTest, createErrorSimple) {
  const auto msg = std::string{
      "\"!ab#c$d%e&f'g(h)i*j+k,l-m.n/o\" this is not a human readable text"};
  auto err = osquery::createError(TestError::AnotherError, msg);
  EXPECT_EQ(TestError::AnotherError, err.getErrorCode());
  EXPECT_FALSE(err.hasUnderlyingError());

  auto shortMsg = err.getFullMessageRecursive();
  EXPECT_PRED2(stringContains, shortMsg, "TestError");
  EXPECT_PRED2(stringContains, shortMsg, msg);
}

GTEST_TEST(ErrorTest, createErrorFromOtherError) {
  const auto firstMsg = std::string{"2018-06-28 08:13 451014"};

  auto firstErr = osquery::createError(TestError::SomeError, firstMsg);
  EXPECT_EQ(TestError::SomeError, firstErr.getErrorCode());
  EXPECT_FALSE(firstErr.hasUnderlyingError());

  EXPECT_PRED2(stringContains, firstErr.getFullMessageRecursive(), firstMsg);

  const auto secondMsg = std::string{"what's wrong with the first message?!"};
  auto secondErr = osquery::createError(
      TestError::AnotherError, secondMsg, std::move(firstErr));
  EXPECT_EQ(TestError::AnotherError, secondErr.getErrorCode());
  EXPECT_TRUE(secondErr.hasUnderlyingError());
  auto secondShortMsg = secondErr.getFullMessageRecursive();
  EXPECT_PRED2(stringContains, secondShortMsg, "TestError");
  EXPECT_PRED2(stringContains, secondShortMsg, firstMsg);
  EXPECT_PRED2(stringContains, secondShortMsg, secondMsg);
}
