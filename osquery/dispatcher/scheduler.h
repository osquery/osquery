/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <chrono>
#include <map>

#include <osquery/dispatcher.h>

#include "osquery/sql/sqlite_util.h"

namespace osquery {

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class SchedulerRunner : public InternalRunnable {
 public:
  SchedulerRunner(unsigned long int timeout, size_t interval)
      : InternalRunnable("SchedulerRunner"),
        interval_(interval),
        timeout_(timeout) {}

 public:
  /// The Dispatcher thread entry point.
  void start() override;

  /// The Dispatcher interrupt point.
  void stop() override {}

 private:
  /// Interval in seconds between schedule steps.
  size_t interval_;

  /// Maximum number of steps.
  unsigned long int timeout_;

  std::chrono::milliseconds sum_overtime_ = std::chrono::milliseconds::zero();
};

SQLInternal monitor(const std::string& name, const ScheduledQuery& query);

/// Start querying according to the config's schedule
void startScheduler();

/// Helper scheduler start with variable settings for testing.
void startScheduler(unsigned long int timeout, size_t interval);
}
