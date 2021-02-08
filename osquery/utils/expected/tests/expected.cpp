/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/optional.hpp>

#include <gtest/gtest.h>
#include <osquery/utils/error/error.h>
#include <osquery/utils/expected/expected.h>

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
  EXPECT_TRUE(value.isValue());
  EXPECT_FALSE(value.isError());
  EXPECT_EQ(value.get(), "Test");
}

GTEST_TEST(ExpectedTest, failure_error_contructor_initialization) {
  Expected<std::string, TestError> error =
      Error<TestError>(TestError::Some, "Please try again");
  EXPECT_FALSE(error);
  EXPECT_FALSE(error.isValue());
  EXPECT_TRUE(error.isError());
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
  EXPECT_TRUE(expected.isError());
  EXPECT_EQ(expected.getErrorCode(), TestError::Some);
  auto fullMsg = expected.getError().getMessage();
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
    return createError(TestError::Logical)
           << "an error message is supposed to be here";
  };
  auto v = giveMeDozen(true);
  EXPECT_TRUE(v);
  ASSERT_FALSE(v.isError());
  EXPECT_EQ(*v, 50011971);

  auto errV = giveMeDozen(false);
  EXPECT_FALSE(errV);
  ASSERT_TRUE(errV.isError());
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
  ASSERT_FALSE(s.isError());

  auto errS = giveMeStatus(false);
  EXPECT_FALSE(errS);
  ASSERT_TRUE(errS.isError());
}

GTEST_TEST(ExpectedTest, nested_errors_example) {
  const auto msg = std::string{"Write a good error message"};
  auto firstFailureSource = [&msg]() -> Expected<std::vector<int>, TestError> {
    return createError(TestError::Semantic) << msg;
  };
  auto giveMeNestedError = [&]() -> Expected<std::vector<int>, TestError> {
    auto ret = firstFailureSource();
    ret.isError();
    return createError(TestError::Runtime, ret.takeError()) << msg;
  };
  auto ret = giveMeNestedError();
  EXPECT_FALSE(ret);
  ASSERT_TRUE(ret.isError());
  EXPECT_EQ(ret.getErrorCode(), TestError::Runtime);
  ASSERT_TRUE(ret.getError().hasUnderlyingError());
  EXPECT_PRED2(stringContains, ret.getError().getMessage(), msg);
}

GTEST_TEST(ExpectedTest, error_handling_example) {
  auto failureSource = []() -> Expected<std::vector<int>, TestError> {
    return createError(TestError::Runtime) << "Test error message ()*+,-.";
  };
  auto ret = failureSource();
  if (ret.isError()) {
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

GTEST_TEST(ExpectedTest, expected_was_not_checked_before_destruction_failure) {
  auto action = []() { auto expected = ExpectedSuccess<TestError>{Success()}; };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Expected was not checked before destruction");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, expected_was_not_checked_before_assigning_failure) {
  auto action = []() {
    auto expected = ExpectedSuccess<TestError>{Success()};
    expected = ExpectedSuccess<TestError>{Success()};
    expected.isValue();
  };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Expected was not checked before assigning");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, expected_move_is_safe) {
  auto expected = ExpectedSuccess<TestError>{Success()};
  expected.isValue();
  expected = ExpectedSuccess<TestError>{Success()};
  expected.isValue();
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

GTEST_TEST(ExpectedTest, get_error_from_expected_with_value) {
  auto action = []() {
    auto expected = Expected<int, TestError>(228);
    const auto& error = expected.getError();
    boost::ignore_unused(error);
  };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Do not try to get error from Expected with value");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, take_error_from_expected_with_value) {
  auto action = []() {
    auto expected = Expected<int, TestError>(228);
    return expected.takeError();
  };
#ifndef NDEBUG
  ASSERT_DEATH(action(), "Do not try to get error from Expected with value");
#else
  boost::ignore_unused(action);
#endif
}

GTEST_TEST(ExpectedTest, value__takeOr) {
  const auto text = std::string{"some text"};
  auto callable = [&text]() -> Expected<std::string, TestError> {
    return text;
  };
  auto expected = callable();
  EXPECT_EQ(expected ? expected.take() : std::string{"default text"}, text);

  EXPECT_EQ(callable().takeOr(std::string{"default text"}), text);
}

GTEST_TEST(ExpectedTest, error__takeOr) {
  auto expected =
      Expected<std::string, TestError>(TestError::Semantic, "error message");
  EXPECT_EQ(expected.takeOr(std::string{"default text"}), "default text");
}

GTEST_TEST(ExpectedTest, error__takeOr_with_user_defined_class) {
  class SomeTestClass {
   public:
    explicit SomeTestClass(const std::string& prefix, const std::string& suffix)
        : text{prefix + " - " + suffix} {}

    std::string text;
  };
  auto callable = []() -> Expected<SomeTestClass, TestError> {
    return createError(TestError::Semantic) << "error message";
  };
  EXPECT_EQ(callable().takeOr(SomeTestClass("427 BC", "347 BC")).text,
            "427 BC - 347 BC");
}

GTEST_TEST(ExpectedTest, value_takeOr_with_rvalue_as_an_argument) {
  auto value = int{312};
  auto callable = []() -> Expected<int, TestError> { return 306; };
  value = callable().takeOr(value);
  EXPECT_EQ(value, 306);
}

GTEST_TEST(ExpectedTest, error_takeOr_with_rvalue_as_an_argument) {
  auto value = int{312};
  auto callable = []() -> Expected<int, TestError> {
    return createError(TestError::Logical) << "error message";
  };
  value = callable().takeOr(value);
  EXPECT_EQ(value, 312);
}

} // namespace osquery
