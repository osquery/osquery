/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/optional.hpp>

#include <gtest/gtest.h>
#include <osquery/error.h>
#include <osquery/expected.h>

namespace osquery {

enum class TestError {
  Some,
  Another,
  Semantic,
  Logical,
  Runtime,
};

GTEST_TEST(ExpectedTest, success_contructor_initialization) {
  Expected<std::string, TestError> value = std::string("Test");
  EXPECT_TRUE(value);
  EXPECT_TRUE(value.isOk());
  EXPECT_EQ(value.get(), "Test");
}

GTEST_TEST(ExpectedTest, failure_error_contructor_initialization) {
  Expected<std::string, TestError> error =
      Error<TestError>(TestError::Some, "Please try again");
  EXPECT_FALSE(error);
  EXPECT_FALSE(error.isOk());
  EXPECT_EQ(error.getErrorCode(), TestError::Some);
}

bool stringContains(const std::string& what, const std::string& where) {
  return boost::contains(what, where);
};

GTEST_TEST(ExpectedTest, failure_error_str_contructor_initialization) {
  const auto msg =
      std::string{"\"#$%&'()*+,-./089:;<[=]>\" is it a valid error message?"};
  auto expected = Expected<std::string, TestError>::failure(msg);
  EXPECT_FALSE(expected);
  EXPECT_FALSE(expected.isOk());
  EXPECT_EQ(expected.getErrorCode(), TestError::Some);
  auto fullMsg = expected.getError().getFullMessage();
  EXPECT_PRED2(stringContains, fullMsg, msg);
}

osquery::ExpectedUnique<std::string, TestError> testFunction() {
  return std::make_unique<std::string>("Test");
}

GTEST_TEST(ExpectedTest, ExpectedSharedTestFunction) {
  osquery::Expected<std::shared_ptr<std::string>, TestError> sharedPointer =
      std::make_shared<std::string>("Test");
  EXPECT_TRUE(sharedPointer);
  EXPECT_EQ(**sharedPointer, "Test");

  osquery::ExpectedShared<std::string, TestError> sharedPointer2 =
      std::make_shared<std::string>("Test");
  EXPECT_TRUE(sharedPointer2);
  EXPECT_EQ(**sharedPointer2, "Test");
}

GTEST_TEST(ExpectedTest, ExpectedUniqueTestFunction) {
  auto uniquePointer = testFunction();
  EXPECT_TRUE(uniquePointer);
  EXPECT_EQ(**uniquePointer, "Test");
}

GTEST_TEST(ExpectedTest, ExpectedSharedWithError) {
  osquery::ExpectedShared<std::string, TestError> error =
      Error<TestError>(TestError::Another, "Some message");
  EXPECT_FALSE(error);
  EXPECT_EQ(error.getErrorCode(), TestError::Another);
}

GTEST_TEST(ExpectedTest, ExpectedOptional) {
  boost::optional<std::string> optional = std::string("123");
  osquery::Expected<boost::optional<std::string>, TestError> optionalExpected =
      optional;
  EXPECT_TRUE(optionalExpected);
  EXPECT_EQ(**optionalExpected, "123");
}

template <typename ValueType>
using LocalExpected = Expected<ValueType, TestError>;

GTEST_TEST(ExpectedTest, createError_example) {
  auto giveMeDozen = [](bool valid) -> LocalExpected<int> {
    if (valid) {
      return 50011971;
    }
    return createError(TestError::Logical,
                       "an error message is supposed to be here");
  };
  auto v = giveMeDozen(true);
  EXPECT_TRUE(v);
  ASSERT_TRUE(v.isOk());
  EXPECT_EQ(*v, 50011971);

  auto errV = giveMeDozen(false);
  EXPECT_FALSE(errV);
  ASSERT_FALSE(errV.isOk());
  EXPECT_EQ(errV.getErrorCode(), TestError::Logical);
}

GTEST_TEST(ExpectedTest, ExpectedSuccess_example) {
  auto giveMeStatus = [](bool valid) -> ExpectedSuccess<TestError> {
    if (valid) {
      return Success{};
    }
    return Error<TestError>(TestError::Runtime,
                            "an error message is supposed to be here");
  };
  auto s = giveMeStatus(true);
  EXPECT_TRUE(s);
  ASSERT_TRUE(s.isOk());

  auto errS = giveMeStatus(false);
  EXPECT_FALSE(errS);
  ASSERT_FALSE(errS.isOk());
}

GTEST_TEST(ExpectedTest, nested_errors_example) {
  const auto msg = std::string{"Write a good error message"};
  auto firstFailureSource = [&msg]() -> Expected<std::vector<int>, TestError> {
    return createError(TestError::Semantic, msg);
  };
  auto giveMeNestedError = [&]() -> Expected<std::vector<int>, TestError> {
    auto ret = firstFailureSource();
    ret.isOk();
    return createError(TestError::Runtime, msg, ret.takeError());
  };
  auto ret = giveMeNestedError();
  EXPECT_FALSE(ret);
  ASSERT_FALSE(ret.isOk());
  EXPECT_EQ(ret.getErrorCode(), TestError::Runtime);
  ASSERT_TRUE(ret.getError().hasUnderlyingError());
  EXPECT_PRED2(stringContains, ret.getError().getFullMessage(), msg);
}

GTEST_TEST(ExpectedTest, error_handling_example) {
  auto failureSource = []() -> Expected<std::vector<int>, TestError> {
    return createError(TestError::Runtime, "Test error message ()*+,-.");
  };
  auto ret = failureSource();
  if (!ret.isOk()) {
    switch (ret.getErrorCode()) {
    case TestError::Some:
    case TestError::Another:
    case TestError::Semantic:
    case TestError::Logical:
      FAIL() << "There is must be a Runtime type of error";
    case TestError::Runtime:
      SUCCEED();
    }
  } else {
    FAIL() << "There is must be an error";
  }
}

GTEST_TEST(ExpectedTest, error_was_not_checked) {
  auto action = []() { auto expected = ExpectedSuccess<TestError>{Success()}; };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Error was not checked");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, get_value_from_expected_with_error) {
  auto action = []() {
    auto expected = Expected<int, TestError>(TestError::Logical,
                                             "Test error message @#$0k+Qh");
    auto value = expected.get();
    boost::ignore_unused(value);
  };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Do not try to get value from Expected with error");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, const_get_value_from_expected_with_error) {
  auto action = []() {
    const auto expected = Expected<int, TestError>(
        TestError::Semantic, "Test error message {}()[].");
    auto value = expected.get();
    boost::ignore_unused(value);
  };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Do not try to get value from Expected with error");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, take_value_from_expected_with_error) {
  auto action = []() {
    auto expected = Expected<int, TestError>(TestError::Semantic,
                                             "Test error message !&^?<>.");
    auto value = expected.take();
    boost::ignore_unused(value);
  };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Do not try to get value from Expected with error");
#else
  boost::ignore_unused(action);
#endif
}

} // namespace osquery
