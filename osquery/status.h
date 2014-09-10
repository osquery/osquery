// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <string>

namespace osquery {

// osquery::Status is a utility class which is used all over osquery to
// express the state of operations.
class Status {
 public:
  // default constructor
  Status() : code_(0), message_("OK") {}

  // constructor which allows you to do something like:
  //   auto s = Status(0, "OK);
  Status(int c, std::string m) : code_(c), message_(m) {}

 public:
  // a getter for the code property
  int getCode() const { return code_; }

  // a getter for the message property
  std::string getMessage() const { return message_; }

  // a convenience method to check if the return code of the status is 0
  bool ok() const { return getCode() == 0; }

  // a synonym for getMessage().
  std::string toString() const { return getMessage(); }

 private:
  int code_;
  std::string message_;
};
}
