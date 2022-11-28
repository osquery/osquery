/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/algorithm/string.hpp>
#include <boost/io/quoted.hpp>

#include <osquery/utils/error/error.h>

enum class TestError {
  SomeError = 1,
  AnotherError = 2,
  MusicError,
};

GTEST_TEST(ErrorTest, initialization) {
  auto error = osquery::Error<TestError>(TestError::SomeError, "TestMessage");
  EXPECT_FALSE(error.hasUnderlyingError());
  EXPECT_TRUE(error == TestError::SomeError);

  auto shortMsg = error.getNonRecursiveMessage();
  EXPECT_NE(std::string::npos, shortMsg.find("TestError[1]"));

  auto fullMsg = error.getMessage();
  EXPECT_NE(std::string::npos, fullMsg.find("TestError[1]"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestMessage"));
}

GTEST_TEST(ErrorTest, recursive) {
  auto originalError = std::make_unique<osquery::Error<TestError>>(
      TestError::SomeError, "SuperTestMessage");
  auto error = osquery::Error<TestError>(
      TestError::AnotherError, "TestMessage", std::move(originalError));
  EXPECT_TRUE(error.hasUnderlyingError());

  auto shortMsg = error.getNonRecursiveMessage();
  EXPECT_EQ(std::string::npos, shortMsg.find("TestError[1]"));
  EXPECT_NE(std::string::npos, shortMsg.find("TestError[2]"));

  auto fullMsg = error.getMessage();
  EXPECT_NE(std::string::npos, fullMsg.find("TestError[1]"));
  EXPECT_NE(std::string::npos, fullMsg.find("SuperTestMessage"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestError[2]"));
  EXPECT_NE(std::string::npos, fullMsg.find("TestMessage"));
}

bool stringContains(const std::string& where, const std::string& what) {
  return boost::contains(where, what);
};

GTEST_TEST(ErrorTest, createErrorSimple) {
  const auto msg = std::string{
      "\"!ab#c$d%e&f'g(h)i*j+k,l-m.n/o\" this is not a human readable text"};
  auto err = osquery::createError(TestError::AnotherError) << msg;
  EXPECT_EQ(TestError::AnotherError, err.getErrorCode());
  EXPECT_FALSE(err.hasUnderlyingError());

  auto shortMsg = err.getMessage();
  EXPECT_PRED2(stringContains, shortMsg, "TestError");
  EXPECT_PRED2(stringContains, shortMsg, msg);
}

GTEST_TEST(ErrorTest, createErrorFromOtherError) {
  const auto firstMsg = std::string{"2018-06-28 08:13 451014"};

  auto firstErr = osquery::createError(TestError::SomeError) << firstMsg;
  EXPECT_EQ(TestError::SomeError, firstErr.getErrorCode());
  EXPECT_FALSE(firstErr.hasUnderlyingError());

  EXPECT_PRED2(stringContains, firstErr.getMessage(), firstMsg);

  const auto secondMsg = std::string{"what's wrong with the first message?!"};
  auto secondErr =
      osquery::createError(TestError::AnotherError, std::move(firstErr))
      << secondMsg;
  EXPECT_EQ(TestError::AnotherError, secondErr.getErrorCode());
  EXPECT_TRUE(secondErr.hasUnderlyingError());
  auto secondShortMsg = secondErr.getMessage();
  EXPECT_PRED2(stringContains, secondShortMsg, "TestError");
  EXPECT_PRED2(stringContains, secondShortMsg, firstMsg);
  EXPECT_PRED2(stringContains, secondShortMsg, secondMsg);
}

GTEST_TEST(ErrorTest, createErrorAndStreamToIt) {
  const auto a4 = std::string{"A4"};
  const auto err = osquery::createError(TestError::MusicError)
                   << "Do" << '-' << "Re"
                   << "-Mi"
                   << "-Fa"
                   << "-Sol"
                   << "-La"
                   << "-Si La" << boost::io::quoted(a4) << ' ' << 440 << " Hz";
  EXPECT_EQ(TestError::MusicError, err.getErrorCode());
  auto fullMsg = err.getMessage();
  EXPECT_PRED2(
      stringContains, fullMsg, "Do-Re-Mi-Fa-Sol-La-Si La\"A4\" 440 Hz");
}
