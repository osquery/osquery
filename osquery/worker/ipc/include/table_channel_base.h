/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <unordered_map>

#include <osquery/utils/only_movable.h>
#include <osquery/utils/status/status.h>

namespace osquery {
template <typename Derived>
class TableChannelBase : only_movable {
 public:
  TableChannelBase() = delete;
  TableChannelBase(const std::string& table_name) : table_name_(table_name) {}

  virtual ~TableChannelBase() {}

  Status sendStringMessage(const std::string& message) {
    return static_cast<Derived&>(*this).sendStringMessageImpl(message);
  }
  Status recvStringMessage(std::string& message) {
    return static_cast<Derived&>(*this).recvStringMessageImpl(message);
  }

  std::string table_name_;
};
} // namespace osquery
