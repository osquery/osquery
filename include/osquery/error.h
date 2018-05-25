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
#include <cxxabi.h>
#include <exception>
#include <functional>
#include <ios>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <typeinfo>

namespace osquery {
class Status;

enum class ExceptionCode {
  Generic = 1,
  Runtime = 2,
  Logic = 3,
  BadCast = 4,
  Bad = 5,
  BadTypeID = 6,
  BadWeakPtr = 7,
  BadFunctionCall = 8,
  BadAlloc = 9,
  BaseIOFailuer = 10,
};

class ErrorBase {
 public:
  virtual std::string getShortMessage() const = 0;
  virtual std::string getFullMessage() const = 0;
  virtual std::string getShortMessageRecursive() const = 0;
  virtual std::string getFullMessageRecursive() const = 0;
  virtual ~ErrorBase(){};
};

template <class T>
class Error : public ErrorBase {
 private:
  static std::string getErrorTypeName() {
    return boost::core::demangle(typeid(T).name());
  }

 public:
  explicit Error(T error_code,
                 std::string message = "",
                 std::shared_ptr<ErrorBase> underlying_error = nullptr)
      : errorCode_(error_code),
        message_(std::move(message)),
        underlyingError_(std::move(underlying_error)) {}

  Error(T error_code, std::exception exception, std::string message = "")
      : errorCode_(error_code),
        message_(std::move(message)),
        underlyingError_(new Error<ExceptionCode>(exception)) {}

  Error(Error&& other) {
    errorCode_ = other.errorCode_;
    message_ = std::move(other.message_);
    underlyingError_ = std::move(other.underlyingError_);
  }

  Error& operator=(Error&& other) {
    if (this != &other) {
      errorCode_ = other.errorCode_;
      message_ = std::move(other.message_);
      underlyingError_ = std::move(other.underlyingError_);
    }
    return *this;
  }

  T getErrorCode() const {
    return errorCode_;
  }

  virtual std::shared_ptr<ErrorBase> getUnderlyingError() const {
    return underlyingError_;
  }

  virtual std::string getShortMessage() const {
    return getErrorTypeName() + " " +
           std::to_string(static_cast<int>(errorCode_));
  }

  virtual std::string getFullMessage() const {
    std::string full_message = getShortMessage();
    if (message_.size() > 0) {
      full_message += " (" + message_ + ")";
    }
    return full_message;
  }

  virtual std::string getShortMessageRecursive() const {
    std::string full_message = getShortMessage();
    if (underlyingError_) {
      full_message += " <- " + underlyingError_->getShortMessageRecursive();
    }
    return full_message;
  }

  virtual std::string getFullMessageRecursive() const {
    std::string full_message = getFullMessage();
    if (underlyingError_) {
      full_message += " <- " + underlyingError_->getFullMessageRecursive();
    }
    return full_message;
  }

  /// Please use Error(domain,error_code,exception,message) for exceptions
  /// Error created from exception does provide enough information
  /// for reporting or error handling
  Error<ExceptionCode>(std::exception exception,
                       ExceptionCode code = ExceptionCode::Generic)
      : errorCode_(code),
        message_(exception.what()),
        underlyingError_(nullptr) {}
  Error(std::runtime_error exception)
      : Error(exception, ExceptionCode::Runtime) {}
  Error(std::logic_error exception) : Error(exception, ExceptionCode::Logic) {}
  Error(std::bad_cast exception) : Error(exception, ExceptionCode::BadCast) {}
  Error(std::bad_exception exception) : Error(exception, ExceptionCode::Bad) {}
  Error(std::bad_typeid exception)
      : Error(exception, ExceptionCode::BadTypeID) {}
  Error(std::bad_weak_ptr exception)
      : Error(exception, ExceptionCode::BadWeakPtr) {}
  Error(std::bad_function_call exception)
      : Error(exception, ExceptionCode::BadFunctionCall) {}
  Error(std::bad_alloc exception) : Error(exception, ExceptionCode::BadAlloc) {}
  Error(std::ios_base::failure exception)
      : Error(exception, ExceptionCode::BaseIOFailuer) {}

 private:
  T errorCode_;
  std::string message_;
  std::shared_ptr<ErrorBase> underlyingError_;
};

template <class T>
inline bool operator==(const Error<T>* lhs, const Error<T>* rhs) {
  return lhs->getErrorCode() == rhs->getErrorCode();
}

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

} // namespace osquery
