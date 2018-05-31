/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <include/osquery/error.h>
#include <sstream>
#include <string>

namespace osquery {

/**
 * @brief A utility class which is used to express the state of operations.
 *
 * @code{.cpp}
 *   osquery::Status foobar() {
 *     auto na = doSomeWork();
 *     if (na->itWorked()) {
 *       return osquery::Status(0, "OK");
 *     } else {
 *       return osquery::Status(1, na->getErrorString());
 *     }
 *   }
 * @endcode
 */

class Status {
 public:
  /**
   * @brief Default constructor
   *
   * Note that the default constructor initialized an osquery::Status instance
   * to a state such that a successful operation is indicated.
   */
  explicit Status(int c = 0) : code_(c), message_("OK") {}

  /**
   * @brief A constructor which can be used to concisely express the status of
   * an operation.
   *
   * @param c a status code. The idiom is that a zero status code indicates a
   * successful operation and a non-zero status code indicates a failed
   * operation.
   * @param m a message indicating some extra detail regarding the operation.
   * If all operations were successful, this message should be "OK".
   * Otherwise, it doesn't matter what the string is, as long as both the
   * setter and caller agree.
   */
  Status(int c, std::string m) : code_(c), message_(std::move(m)) {}

  Status(const ErrorBase& error)
      : code_(1), message_(error.getFullMessageRecursive()) {}

 public:
  /**
   * @brief A getter for the status code property
   *
   * @return an integer representing the status code of the operation.
   */
  int getCode() const {
    return code_;
  }

  /**
   * @brief A getter for the message property
   *
   * @return a string representing arbitrary additional information about the
   * success or failure of an operation. On successful operations, the idiom
   * is for the message to be "OK"
   */
  std::string getMessage() const {
    return message_;
  }

  /**
   * @brief A convenience method to check if the return code is 0
   *
   * @code{.cpp}
   *   auto s = doSomething();
   *   if (s.ok()) {
   *     LOG(INFO) << "doing work";
   *   } else {
   *     LOG(ERROR) << s.toString();
   *   }
   * @endcode
   *
   * @return a boolean which is true if the status code is 0, false otherwise.
   */
  bool ok() const {
    return getCode() == 0;
  }

  /**
   * @brief A synonym for osquery::Status::getMessage()
   *
   * @see getMessage()
   */
  std::string toString() const {
    return getMessage();
  }
  std::string what() const {
    return getMessage();
  }

  /**
   * @brief implicit conversion to bool
   *
   * Allows easy use of Status in an if statement, as below:
   *
   * @code{.cpp}
   *   if (doSomethingThatReturnsStatus()) {
   *     LOG(INFO) << "Success!";
   *   }
   * @endcode
   */
  /* explicit */ explicit operator bool() const {
    return ok();
  }

  // Below operator implementations useful for testing with gtest

  // Enables use of gtest (ASSERT|EXPECT)_EQ
  bool operator==(const Status& rhs) const {
    return (code_ == rhs.getCode()) && (message_ == rhs.getMessage());
  }

  // Enables use of gtest (ASSERT|EXPECT)_NE
  bool operator!=(const Status& rhs) const {
    return !operator==(rhs);
  }

  // Enables pretty-printing in gtest (ASSERT|EXPECT)_(EQ|NE)
  friend ::std::ostream& operator<<(::std::ostream& os, const Status& s);

 private:
  /// the internal storage of the status code
  int code_;

  /// the internal storage of the status message
  std::string message_;
};
} // namespace osquery
