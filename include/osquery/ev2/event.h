/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <chrono>

namespace osquery {
namespace ev2 {

using EventId = uint64_t;
using EventTime = std::chrono::system_clock::time_point;

class Event {
 public:
  explicit Event(EventId id, EventTime time);
  virtual ~Event() = default;

  const EventId id;
  const EventTime time;
};

} // namespace ev2
} // namespace osquery
