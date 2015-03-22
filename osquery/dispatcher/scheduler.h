/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include "osquery/dispatcher/dispatcher.h"

namespace osquery {

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class SchedulerRunner : public InternalRunnable {
 public:
  virtual ~SchedulerRunner() {}
  SchedulerRunner(unsigned long int timeout, size_t interval)
      : interval_(interval), timeout_(timeout) {}

 public:
  /// The Dispatcher thread entry point.
  void enter();

 protected:
  /// The UNIX domain socket path for the ExtensionManager.
  std::map<std::string, size_t> splay_;
  /// Interval in seconds between schedule steps.
  size_t interval_;
  /// Maximum number of steps.
  unsigned long int timeout_;
};

/// Start quering according to the config's schedule
Status startScheduler();

/// Helper scheduler start with variable settings for testing.
Status startScheduler(unsigned long int timeout, size_t interval);
}
