/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>
#include <map>

#include <osquery/dispatcher/dispatcher.h>

#include "osquery/sql/sqlite_util.h"

namespace osquery {

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class SchedulerRunner : public InternalRunnable {
 public:
  SchedulerRunner(
      unsigned long int timeout,
      size_t interval,
      std::chrono::milliseconds max_time_drift = std::chrono::seconds::zero())
      : InternalRunnable("SchedulerRunner"),
        interval_{std::chrono::seconds{interval}},
        timeout_(timeout),
        time_drift_{std::chrono::milliseconds::zero()},
        max_time_drift_{max_time_drift} {}

 public:
  /// The Dispatcher thread entry point.
  void start() override;

  /// The Dispatcher interrupt point.
  void stop() override {}

  /// Accumulated for some time time drift to compensate.
  std::chrono::milliseconds getCurrentTimeDrift() const noexcept;

 private:
  void calculateTimeDriftAndMaybePause(
      std::chrono::milliseconds loop_step_duration);

  /// Check interval-based decorators.
  void maybeRunDecorators(uint64_t time_step);

  /// Check relative configuration flags.
  void maybeReloadSchedule(uint64_t time_step);

  /// Check if buffered status logs should be flushed.
  void maybeFlushLogs(uint64_t time_step);

  /// Check if carve requests should be scheduled.
  void maybeScheduleCarves(uint64_t time_step);

 private:
  /// Interval in seconds between schedule steps.
  const std::chrono::milliseconds interval_;

  /// Maximum number of steps.
  unsigned long int timeout_;

  /// Accumulated for some time time drift to compensate.
  /// It will be either reduced during compensation process or
  /// after exceding the limit @see max_time_drift_
  std::chrono::milliseconds time_drift_;

  const std::chrono::milliseconds max_time_drift_;

  /// Tests should not always trigger a shutdown when the scheduler expires,
  /// so let tests decide when this should happen.
  FRIEND_TEST(TLSConfigTests, test_runner_and_scheduler);
  bool request_shutdown_on_expiration{true};
};

SQLInternal monitor(const std::string& name, const ScheduledQuery& query);

/// Start querying according to the config's schedule
void startScheduler();

/// Helper scheduler start with variable settings for testing.
void startScheduler(unsigned long int timeout, size_t interval);
} // namespace osquery
