/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cassert>
#include <memory>
#include <string>
#include <type_traits>

#include <osquery/utils/error/error.h>

#include <boost/blank.hpp>
#include <boost/variant.hpp>

#include <osquery/utils/debug/debug_only.h>

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
 *      return Error<TestError>(TestError::SomeError, "some error message");
 *    } else {
 *      return createError(TestError::SomeError) << "one more error message";
 *    }
 *   }
 * }
 *
 * Expected:
 * ExpectedUnique<PlatformProcess, TestError> function() {
 *   if (test) {
 *    return std::make_unique<PlatformProcess>(pid);
 *   } else {
 *    return createError(TestError::AnotherError) << "something wrong";
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
 * @see osquery/utils/expected/tests/expected.cpp for more examples.
 *
 * Rvalue ref-qualified methods of unconditional access value or error are
 * explicitly deleted. As far as `osquery` does not have an exceptions we
 * definitely would like to avoid using unsafe way of getting either value or
 * error without a proper check in advance.
 */

namespace osquery {

template <typename ValueType_, typename ErrorCodeEnumType>
class Expected final {
 public:
  using ValueType = ValueType_;
  using ErrorType = Error<ErrorCodeEnumType>;
  using SelfType = Expected<ValueType, ErrorCodeEnumType>;

  static_assert(
      !std::is_pointer<ValueType>::value,
      "Please do not use raw pointers as expected value, "
      "use smart pointers instead. See CppCoreGuidelines for explanation. "
      "https://github.com/isocpp/CppCoreGuidelines/blob/master/"
      "CppCoreGuidelines.md#Rf-unique_ptr");
  static_assert(!std::is_reference<ValueType>::value,
                "Expected does not support reference as a value type");
  static_assert(std::is_enum<ErrorCodeEnumType>::value,
                "ErrorCodeEnumType template parameter must be enum");

 public:
  Expected(ValueType value) : object_{std::move(value)} {}

  Expected(ErrorType error) : object_{std::move(error)} {}

  explicit Expected(ErrorCodeEnumType code, std::string message)
      : object_{ErrorType(code, message)} {}

  Expected() = delete;
  Expected(ErrorBase* error) = delete;

  Expected(Expected&& other)
      : object_(std::move(other.object_)), errorChecked_(other.errorChecked_) {
    other.errorChecked_.set(true);
  }

  Expected& operator=(Expected&& other) {
    if (this != &other) {
      errorChecked_.verify("Expected was not checked before assigning");

      object_ = std::move(other.object_);
      errorChecked_ = other.errorChecked_;
      other.errorChecked_.set(true);
    }
    return *this;
  }

  Expected(const Expected&) = delete;
  Expected& operator=(const Expected& other) = delete;

  ~Expected() {
    errorChecked_.verify("Expected was not checked before destruction");
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

  ErrorType takeError() && = delete;
  ErrorType takeError() & {
    verifyIsError();
    return std::move(boost::get<ErrorType>(object_));
  }

  const ErrorType& getError() const&& = delete;
  const ErrorType& getError() const& {
    verifyIsError();
    return boost::get<ErrorType>(object_);
  }

  ErrorCodeEnumType getErrorCode() const&& = delete;
  ErrorCodeEnumType getErrorCode() const& {
    return getError().getErrorCode();
  }

  bool isError() const noexcept {
    errorChecked_.set(true);
    return object_.which() == kErrorType_;
  }

  void ignoreResult() const noexcept {
    errorChecked_.set(true);
  }

  bool isValue() const noexcept {
    return !isError();
  }

  explicit operator bool() const noexcept {
    return isValue();
  }

  ValueType& get() && = delete;
  ValueType& get() & {
    verifyIsValue();
    return boost::get<ValueType>(object_);
  }

  const ValueType& get() const&& = delete;
  const ValueType& get() const& {
    verifyIsValue();
    return boost::get<ValueType>(object_);
  }

  ValueType take() && = delete;
  ValueType take() & {
    return std::move(get());
  }

  template <typename ValueTypeUniversal = ValueType>
  typename std::enable_if<
      std::is_same<typename std::decay<ValueTypeUniversal>::type,
                   ValueType>::value,
      ValueType>::type
  takeOr(ValueTypeUniversal&& defaultValue) {
    if (isError()) {
      return std::forward<ValueTypeUniversal>(defaultValue);
    }
    return std::move(get());
  }

  ValueType* operator->() && = delete;
  ValueType* operator->() & {
    return &get();
  }

  const ValueType* operator->() const&& = delete;
  const ValueType* operator->() const& {
    return &get();
  }

  ValueType& operator*() && = delete;
  ValueType& operator*() & {
    return get();
  }

  const ValueType& operator*() const&& = delete;
  const ValueType& operator*() const& {
    return get();
  }

 private:
  inline void verifyIsError() const {
    debug_only::verify([this]() { return object_.which() == kErrorType_; },
                       "Do not try to get error from Expected with value");
  }

  inline void verifyIsValue() const {
    debug_only::verify([this]() { return object_.which() == kValueType_; },
                       "Do not try to get value from Expected with error");
  }

 private:
  boost::variant<ValueType, ErrorType> object_;
  enum ETypeId {
    kValueType_ = 0,
    kErrorType_ = 1,
  };
  debug_only::Var<bool> errorChecked_ = false;
};

template <typename ValueType, typename ErrorCodeEnumType>
using ExpectedShared = Expected<std::shared_ptr<ValueType>, ErrorCodeEnumType>;

template <typename ValueType, typename ErrorCodeEnumType>
using ExpectedUnique = Expected<std::unique_ptr<ValueType>, ErrorCodeEnumType>;

using Success = boost::blank;

template <typename ErrorCodeEnumType>
using ExpectedSuccess = Expected<Success, ErrorCodeEnumType>;

} // namespace osquery
