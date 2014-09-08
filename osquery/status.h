// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_STATUS_H
#define OSQUERY_STATUS_H

#include <string>

namespace osquery {

class Status {
 public:
  Status() : code_(0), message_("OK") {}
  Status(int c, std::string m) : code_(c), message_(m) {}

 public:
  int getCode() { return code_; }
  std::string getMessage() { return message_; }
  bool ok() { return getCode() == 0; }
  std::string toString() { return getMessage(); }

 private:
  int code_;
  std::string message_;
};
}

#endif /* OSQUERY_STATUS_H */
