/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
