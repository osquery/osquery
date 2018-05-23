/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/error.h>
#include <osquery/status.h>

namespace osquery {

Error::Error(std::string domain,
             int error_code,
             std::string message,
             std::shared_ptr<Error> underlying_error)
    : domain_(std::move(domain)),
      errorCode_(error_code),
      message_(std::move(message)),
      underlyingError_(std::move(underlying_error)) {}

Error::Error(Status status)
    : domain_("osquery::Status"),
      errorCode_(status.getCode()),
      message_(status.getMessage()),
      underlyingError_(nullptr) {}

Error::Error(std::exception exception, int error_code)
    : domain_(kExceptionDomain),
      errorCode_(error_code),
      message_(exception.what()),
      underlyingError_(nullptr) {}

Error::Error(std::string domain,
             int error_code,
             std::exception exception,
             std::string message)
    : domain_(std::move(domain)),
      errorCode_(error_code),
      message_(std::move(message)),
      underlyingError_(new Error(exception)) {}

Error::Error(std::runtime_error exception)
    : Error(exception, kRuntimeException) {}
Error::Error(std::logic_error exception) : Error(exception, kLogicException) {}
Error::Error(std::bad_cast exception) : Error(exception, kBadCastException) {}
Error::Error(std::bad_exception exception) : Error(exception, kBadExcpetion) {}
Error::Error(std::bad_typeid exception)
    : Error(exception, kBadTypeIDExcpetion) {}
Error::Error(std::bad_weak_ptr exception)
    : Error(exception, kBadWeakPtrExcpetion) {}
Error::Error(std::bad_function_call exception)
    : Error(exception, kBadFunctionCallExcpetion) {}
Error::Error(std::bad_alloc exception) : Error(exception, kBadAllocExcpetion) {}
Error::Error(std::ios_base::failure exception)
    : Error(exception, kBaseIOFailuerExcpetion) {}

Error::Error(Error&& other) {
  domain_ = std::move(other.domain_);
  errorCode_ = other.errorCode_;
  message_ = std::move(other.message_);
}

std::string Error::getShortMessage() const {
  return domain_ + " " + std::to_string(errorCode_);
}

std::string Error::getFullMessage() const {
  std::string full_message = getShortMessage();
  if (message_.size() > 0) {
    full_message += " (" + message_ + ")";
  }
  return full_message;
}

std::string Error::getShortMessageRecursive() const {
  std::string full_message = getShortMessage();
  if (underlyingError_) {
    full_message += " <- " + underlyingError_->getShortMessageRecursive();
  }
  return full_message;
}

std::string Error::getFullMessageRecursive() const {
  std::string full_message = getFullMessage();
  if (underlyingError_) {
    full_message += " <- " + underlyingError_->getFullMessageRecursive();
  }
  return full_message;
}

std::ostream& operator<<(std::ostream& out, const Error& point) {
  out << point.getFullMessageRecursive();
  return out;
}

} // namespace osquery
