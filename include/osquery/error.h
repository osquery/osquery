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

static const std::string kExceptionDomain{"std::exception"};

enum ExceptionCode : int {
  kGenericException = 1, // generic exception code
  kRuntimeException,
  kLogicException,
  kBadCastException,
  kBadExcpetion,
  kBadTypeIDExcpetion,
  kBadWeakPtrExcpetion,
  kBadFunctionCallExcpetion,
  kBadAllocExcpetion,
  kBaseIOFailuerExcpetion,
};

class Error {
 public:
  Error(std::string domain,
        int error_code,
        std::string message = "",
        std::shared_ptr<Error> underlying_error = nullptr);
  Error(std::string domain,
        int error_code,
        std::exception exception,
        std::string message = "");

  Error(Status status);

  Error& operator=(Error&& other) {
    if (this != &other) {
      domain_ = std::move(other.domain_);
      errorCode_ = other.errorCode_;
      message_ = std::move(other.message_);
    }
    return *this;
  }

  Error(Error&& other);

  std::string getDomain() const {
    return domain_;
  }

  int getErrorCode() const {
    return errorCode_;
  }

  std::shared_ptr<Error> getUnderlyingError() const {
    return underlyingError_;
  }

  std::string getShortMessage() const;

  std::string getFullMessage() const;

  std::string getShortMessageRecursive() const;

  std::string getFullMessageRecursive() const;

  bool operator==(const Error* rhs) const {
    return (errorCode_ == rhs->errorCode_ && domain_ == rhs->domain_);
  }
  bool operator==(const std::string rhs) const {
    return (domain_ == rhs);
  }
  bool operator==(const int rhs) const {
    return (errorCode_ == rhs);
  }
  bool operator==(const std::pair<std::string, int> pair) const {
    return (errorCode_ == pair.second && domain_ == pair.first);
  }
  bool operator==(const Error& rhs) const {
    return (errorCode_ == rhs.errorCode_ && domain_ == rhs.domain_);
  }

 private:
  /// Please use Error(domain,error_code,exception,message) for exceptions
  /// Error created from exception does provide enough information
  /// for reporting or error handling
  Error(std::exception excpetion, int error_code = kGenericException);
  Error(std::runtime_error exception);
  Error(std::logic_error exception);
  Error(std::bad_cast exception);
  Error(std::bad_exception exception);
  Error(std::bad_typeid exception);
  Error(std::bad_weak_ptr exception);
  Error(std::bad_function_call exception);
  Error(std::bad_alloc exception);
  Error(std::ios_base::failure exception);

  std::string domain_;
  int errorCode_;
  std::string message_;
  std::shared_ptr<Error> underlyingError_;
};

std::ostream& operator<<(std::ostream& out, const Error& point);

} // namespace osquery
