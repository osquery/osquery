/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/ev2/event.h>

#include <string>
#include <typeindex>

namespace osquery {
namespace ev2 {

class Subscription {
 public:
  explicit Subscription(
      const std::string& subscriber,
      const std::type_index& pub_type);
  virtual ~Subscription() = default;

  const std::string& subscriber() const;
  const std::type_index& pub_type() const;

  virtual unsigned int avail() const = 0;
  virtual unsigned int wait(
      unsigned int batch = 1,
      std::chrono::milliseconds timeout = std::chrono::milliseconds::zero()
      ) = 0;
  virtual void abort() = 0;

 private:
  const std::string subscriber_;
  const std::type_index pub_type_;
};

} // namespace ev2
} // namespace osquery
