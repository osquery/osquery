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

#include <string>

namespace osquery {
class Error {
 public:
  Error(std::string domain,
        int error_code,
        std::string message = "",
        std::shared_ptr<Error> underlying_error = nullptr);

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
  std::string domain_;
  int errorCode_;
  std::string message_;
  std::shared_ptr<Error> underlyingError_;
};

} // namespace osquery
