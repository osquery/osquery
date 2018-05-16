//
//  error.cpp
//  gmock
//
//  Created by Max Kareta on 5/15/18.
//

#include "error.h"

namespace osquery {

Error::Error(std::string domain,
             int error_code,
             std::string message,
             std::shared_ptr<Error> underlying_error)
    : domain_(domain),
      errorCode_(error_code),
      message_(message),
      underlyingError_(underlying_error) {}

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

} // namespace osquery
