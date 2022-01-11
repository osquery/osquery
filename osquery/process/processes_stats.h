/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/circular_buffer.hpp>
#include <gtest/gtest_prod.h>

#include <osquery/core/flags.h>

namespace osquery {

DECLARE_uint32(processes_stats_cpu_peak_samples);

struct ProcessStatsState {
  std::uint64_t cpu_time{0};
  std::uint64_t process_start_time{0};
  std::uint32_t generation{0};
  std::uint16_t cpu_peak_usage{0};
  boost::circular_buffer<std::uint16_t> cpu_usages{
      FLAGS_processes_stats_cpu_peak_samples};
};

struct ProcessStatsSample {
  std::uint16_t cpu_peak_usage{0};
  std::uint16_t cpu_usage{0};
};

class ProcessesStats {
 public:
  static std::shared_ptr<ProcessesStats>& getInstance();

  std::optional<ProcessStatsSample> getProcessStats(std::uint32_t pid);

  /**
   * @brief Adds or updates the statistics for a process
   *
   * @param pid Pid of the process to update
   * @param total_cpu_time New value of the cpu time used by the process
   * @param update_interval Interval used to calculate the cpu usage
   */
  void updateProcessStats(std::uint32_t pid,
                          std::uint64_t total_cpu_time,
                          std::uint64_t process_start_time,
                          std::uint32_t update_interval);

  /**
   * @brief Increases the current generation the new samples
   * are expected to be at.
   */
  void increaseGeneration();

  /**
   * @brief Cleans old processes stats, every 10 generations or every minute
   * whichever comes first
   *
   * Every 10 generations or every minute, whichever comes first,
   * removes all the processes stats which have a generation
   * older than the current, because it means we have not seen those processes
   * at least one time, which further means that those processes have exited.
   */
  void cleanupProcessStats();

 private:
  std::mutex process_stats_lock_;
  std::atomic<std::uint32_t> current_generation_{0};

  std::unordered_map<std::uint32_t, ProcessStatsState> processes_stats_states_;
};
} // namespace osquery
