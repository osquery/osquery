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

#include <boost/core/demangle.hpp>
#include <memory>
#include <new>
#include <sstream>
#include <string>
#include <typeinfo>

namespace osquery {

class ErrorBase {
 public:
  virtual std::string getShortMessage() const = 0;
  virtual std::string getFullMessage() const = 0;
  virtual std::string getShortMessageRecursive() const = 0;
  virtual std::string getFullMessageRecursive() const = 0;
  virtual ~ErrorBase(){};
};

template <typename ErrorCodeEnumType>
class Error final : public ErrorBase {
 private:
  static std::string getErrorTypeName() {
    return boost::core::demangle(typeid(ErrorCodeEnumType).name());
  }

 public:
  using SelfType = Error<ErrorCodeEnumType>;

  explicit Error(ErrorCodeEnumType error_code,
                 std::string message,
                 std::unique_ptr<ErrorBase> underlying_error = nullptr)
      : errorCode_(error_code),
        message_(std::move(message)),
        underlyingError_(std::move(underlying_error)) {}

  virtual ~Error() = default;

  Error(Error&& other) = default;
  Error(const Error& other) = delete;

  Error& operator=(Error&& other) = default;
  Error& operator=(const Error& other) = delete;

  ErrorCodeEnumType getErrorCode() const {
    return errorCode_;
  }

  bool hasUnderlyingError() const {
    return underlyingError_ != nullptr;
  }

  const ErrorBase& getUnderlyingError() const {
    return *underlyingError_;
  }

  std::unique_ptr<ErrorBase> takeUnderlyingError() const {
    return std::move(underlyingError_);
  }

  std::string getShortMessage() const override {
    return getErrorTypeName() + " " +
           std::to_string(static_cast<int>(errorCode_));
  }

  std::string getFullMessage() const override {
    std::string full_message = getShortMessage();
    if (message_.size() > 0) {
      full_message += " (" + message_ + ")";
    }
    return full_message;
  }

  std::string getShortMessageRecursive() const override {
    std::string full_message = getShortMessage();
    if (underlyingError_) {
      full_message += " <- " + underlyingError_->getShortMessageRecursive();
    }
    return full_message;
  }

  std::string getFullMessageRecursive() const override {
    std::string full_message = getFullMessage();
    if (underlyingError_) {
      full_message += " <- " + underlyingError_->getFullMessageRecursive();
    }
    return full_message;
  }

  void appendToMessage(const std::string& text) {
    message_.append(text);
  }

 private:
  ErrorCodeEnumType errorCode_;
  std::string message_;
  std::unique_ptr<ErrorBase> underlyingError_;
};

template <class T>
inline bool operator==(const Error<T>& lhs, const Error<T>& rhs) {
  return lhs.getErrorCode() == rhs.getErrorCode();
}

template <class T>
inline bool operator==(const Error<T>* lhs, const T rhs) {
  return lhs->getErrorCode() == rhs;
}

template <class T>
inline bool operator==(const Error<T>& lhs, const T rhs) {
  return lhs.getErrorCode() == rhs;
}

template <class T>
inline bool operator==(const ErrorBase& lhs, const T rhs) {
  try {
    const Error<T>& casted_lhs = dynamic_cast<const Error<T>&>(lhs);
    return casted_lhs == rhs;
  } catch (std::bad_cast _) {
    return false;
  }
}

template <class T>
inline bool operator==(const ErrorBase* lhs, const T rhs) {
  auto casted_lhs = dynamic_cast<const Error<T>*>(lhs);
  return casted_lhs != nullptr && casted_lhs == rhs;
}

inline std::ostream& operator<<(std::ostream& out, const ErrorBase& error) {
  out << error.getFullMessageRecursive();
  return out;
}

template <typename ErrorCodeEnumType>
Error<ErrorCodeEnumType> createError(
    ErrorCodeEnumType error_code,
    std::string message,
    std::unique_ptr<ErrorBase> underlying_error = nullptr) {
  return Error<ErrorCodeEnumType>(
      error_code, std::move(message), std::move(underlying_error));
}

template <typename ErrorCodeEnumType, typename OtherErrorCodeEnumType>
Error<ErrorCodeEnumType> createError(
    ErrorCodeEnumType error_code,
    std::string message,
    Error<OtherErrorCodeEnumType> underlying_error) {
  return Error<ErrorCodeEnumType>(
      error_code,
      std::move(message),
      std::make_unique<Error<OtherErrorCodeEnumType>>(
          std::move(underlying_error)));
}

template <typename ErrorType,
          typename ValueType,
          typename = typename std::enable_if<
              std::is_base_of<ErrorBase, ErrorType>::value>::type>
inline ErrorType operator<<(ErrorType&& error, const ValueType& value) {
  std::ostringstream ostr{};
  ostr << value;
  error.appendToMessage(ostr.str());
  return std::forward<ErrorType>(error);
}

} // namespace osquery
