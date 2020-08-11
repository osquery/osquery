/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/tracing/types.h>

#include <string>

namespace osquery {
namespace tracing {

/**
 * Wrapper for the native linux system events, see
 * "/sys/kernel/debug/tracing/events/"
 */
class NativeEvent final {
 public:
  ~NativeEvent();

  NativeEvent(NativeEvent&& other);
  NativeEvent& operator=(NativeEvent&& other);

  NativeEvent(NativeEvent const&) = delete;
  NativeEvent& operator=(NativeEvent const&) = delete;

  enum class Error {
    Unknown = 1,
    System = 2,
  };

  /**
   * Enable event type with path @event_path and receive the id
   */
  static Expected<NativeEvent, NativeEvent::Error> load(std::string event_path);

  SystemEventId id() const;

 private:
  explicit NativeEvent(std::string event_path);

  bool isEnabled() const;
  ExpectedSuccess<Error> enable(bool do_enable);

 private:
  SystemEventId id_ = -1;
  std::string event_path_;
};

} // namespace tracing
} // namespace osquery
