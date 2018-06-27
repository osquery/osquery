/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <memory>
#include <osquery/error.h>
#include <string>
#include <type_traits>
#include <utility>

#include <boost/blank.hpp>
#include <boost/variant.hpp>

/**
 * Utility class that should be used in function that return
 * either error or value. Expected enforce developer to test for success and
 * check error if any.
 *
 * enum class TestError { SomeError = 1, AnotherError = 2 };
 * Expected<std::string, TestError> function() {
 *   if (test) {
 *    return "ok";
 *   } else {
 *    if (first_error) {
 *      return Error<TestError>>(TestError::SomeError, "some error message");
 *    } else {
 *      return createError(TestError::SomeError, "one more error message");
 *    }
 *   }
 * }
 *
 * Expected:
 * ExpectedUnique<PlatformProcess, TestError> function() {
 *   if (test) {
 *    return std::make_unique<PlatformProcess>(pid);
 *   } else {
 *    return createError(TestError::AnotherError, "something wrong");
 *   }
 * }
 *
 * auto result = function();
 * if (result) {
 *   ...use *result
 * } else {
 *   switch (result.getErrorCode()) {
 *     case TestError::SomeError:
 *        ...do something with it
 *        break;
 *     case TestError::AnotherError:
 *        ...do something with it
 *        break;
 *   }
 * }
 * @see osquery/core/tests/exptected_tests.cpp for more examples
 */

namespace osquery {

using Success = boost::blank;

template <typename ValueType_, typename ErrorCodeEnumType>
class Expected final {
 public:
  using ValueType = ValueType_;
  using ErrorType = Error<ErrorCodeEnumType>;
  using SelfType = Expected<ValueType, ErrorCodeEnumType>;

 public:
  Expected(ValueType value) : object_{std::move(value)} {}

  Expected(ErrorType error) : object_{std::move(error)} {}

  explicit Expected(ErrorCodeEnumType code, std::string message)
      : object_{ErrorType(code, message)} {}

  Expected(Expected&& other) = default;

  Expected() = delete;
  Expected(const Expected&) = delete;
  Expected(ErrorBase* error) = delete;

  Expected& operator=(Expected&& other) = default;
  Expected& operator=(const Expected& other) = delete;

  ~Expected() {
    assert(errorChecked_ && "Error was not checked");
  }

  static SelfType success(ValueType value) {
    return SelfType{std::move(value)};
  }

  static SelfType failure(std::string message) {
    auto defaultCode = ErrorCodeEnumType{};
    return SelfType(defaultCode, std::move(message));
  }

  static SelfType failure(ErrorCodeEnumType code, std::string message) {
    return SelfType(code, std::move(message));
  }

  ErrorType takeError() {
    return std::move(boost::get<ErrorType>(object_));
  }

  const ErrorType& getError() const {
    return boost::get<ErrorType>(object_);
  }

  ErrorCodeEnumType getErrorCode() const {
    return getError().getErrorCode();
  }

  bool isOk() const {
#ifndef NDEBUG
    errorChecked_ = true;
#endif
    return object_.which() == kValueType_;
  }

  explicit operator bool() const {
    return isOk();
  }

  ValueType& get() {
    return boost::get<ValueType>(object_);
  }

  const ValueType& get() const {
    return boost::get<ValueType>(object_);
  }

  ValueType take() {
    return std::move(boost::get<ValueType>(object_));
  }

  ValueType* operator->() {
    return &boost::get<ValueType>(object_);
  }

  const ValueType* operator->() const {
    return &boost::get<ValueType>(object_);
  }

  ValueType& operator*() {
    return get();
  }

  const ValueType& operator*() const {
    return get();
  }

 private:
  static_assert(
      !std::is_pointer<ValueType>::value,
      "Please do not use raw pointers as expected value, "
      "use smart pointers instead. See CppCoreGuidelines for explanation. "
      "https://github.com/isocpp/CppCoreGuidelines/blob/master/"
      "CppCoreGuidelines.md#Rf-unique_ptr");
  static_assert(std::is_enum<ErrorCodeEnumType>::value,
                "ErrorCodeEnumType template parameter must be enum");

  boost::variant<ValueType, ErrorType> object_;
  enum ETypeId {
    kValueType_ = 0,
    kErrorType_ = 1,
  };
#ifndef NDEBUG
  mutable bool errorChecked_ = false;
#endif
};

template <typename ValueType, typename ErrorCodeEnumType>
using ExpectedShared = Expected<std::shared_ptr<ValueType>, ErrorCodeEnumType>;

template <typename ValueType, typename ErrorCodeEnumType>
using ExpectedUnique = Expected<std::unique_ptr<ValueType>, ErrorCodeEnumType>;

template <typename ErrorCodeEnumType>
using ExpectedSuccess = Expected<Success, ErrorCodeEnumType>;

} // namespace osquery
