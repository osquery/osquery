/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/ev2/subscription.h>

#include <memory>
#include <string>

namespace osquery {
namespace ev2 {

class Publisher {
 public:
  explicit Publisher(const std::string& name)
    : name_(name)
  { }
  virtual ~Publisher() = default;

  const std::string& name() const;

  virtual void subscribe(std::shared_ptr<Subscription> subscription) = 0;

 private:
  const std::string name_;
};

} // namespace ev2
} // namespace osquery
