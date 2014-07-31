// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_CORE_STATUS_H
#define OSQUERY_CORE_STATUS_H

#include <string>

namespace osquery { namespace core {

class Status {
public:
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

}}

#endif /* OSQUERY_CORE_STATUS_H */
