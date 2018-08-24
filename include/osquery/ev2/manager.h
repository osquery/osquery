/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/ev2/publisher.h>
#include <osquery/ev2/subscription.h>

#include <memory>
#include <typeindex>
#include <unordered_map>
#include <utility>

namespace osquery {
namespace ev2 {

class EventManager {
 public:
  EventManager() = default;

  EventManager(const EventManager&) = delete;
  EventManager& operator=(const EventManager&) = delete;

  void bind(std::shared_ptr<Subscription> sub);
  void register_publisher(std::shared_ptr<Publisher> pub);

 private:
  std::unordered_map<std::type_index, std::shared_ptr<Publisher> > publishers_;
};

} // namespace ev2
} // namespace osquery
