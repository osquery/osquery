/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "processes_stats.h"

#include <sstream>

#include <osquery/logger/logger.h>
#include <osquery/utils/system/time.h>

namespace osquery {

CLI_FLAG(bool,
         enable_processes_stats,
         false,
         "Enables the service that collects processes stats");

CLI_FLAG(uint32,
         processes_stats_interval,
         2,
         "Seconds that the processes stats service waits between scans");

CLI_FLAG(
    bool,
    processes_stats_worker_only,
    false,
    "Enables process stats collection only for the osquery worker process");

CLI_FLAG(uint32,
         processes_stats_cpu_peak_samples,
         30,
         "How many past cpu usage samples to use to calculate the cpu peak "
         "usage");

std::shared_ptr<ProcessesStats>& ProcessesStats::getInstance() {
  static auto processes_stats = std::make_shared<ProcessesStats>();
  return processes_stats;
}

std::optional<ProcessStatsSample> ProcessesStats::getProcessStats(
    std::uint32_t pid) {
  std::lock_guard<std::mutex> process_stats_lock_guard(process_stats_lock_);
  auto proc_it = processes_stats_states_.find(pid);
  if (proc_it == processes_stats_states_.end()) {
    return std::nullopt;
  }

  return ProcessStatsSample{proc_it->second.cpu_peak_usage,
                            proc_it->second.cpu_usages.empty()
                                ? static_cast<std::uint16_t>(0)
                                : proc_it->second.cpu_usages.back()};
}

void ProcessesStats::updateProcessStats(std::uint32_t pid,
                                        std::uint64_t total_cpu_time,
                                        std::uint64_t process_start_time,
                                        std::uint32_t update_interval) {
  std::lock_guard<std::mutex> process_stats_lock_guard(process_stats_lock_);
  auto proc_it = processes_stats_states_.find(pid);

  if (proc_it == processes_stats_states_.end()) {
    processes_stats_states_.emplace(
        pid,
        ProcessStatsState{
            total_cpu_time, process_start_time, current_generation_.load()});
    return;
  }

  auto& proc_stats = proc_it->second;

  /* If the new process cpu time is lower than what we have cached,
     or if the new process start time is not the same of the processwe have
     cached, then we should reset everything and use this new sample alone,
     since these are signals that the process is not the same anymore
     and pid reuse happened */
  if (proc_stats.cpu_time > total_cpu_time ||
      proc_stats.process_start_time != process_start_time) {
    processes_stats_states_.erase(proc_it);
    processes_stats_states_.emplace(
        pid,
        ProcessStatsState{
            total_cpu_time, process_start_time, current_generation_.load()});
    return;
  }

  auto delta_cpu_time = total_cpu_time - proc_stats.cpu_time;
  auto new_cpu_usage = static_cast<uint16_t>(delta_cpu_time * 100ULL /
                                             (update_interval * 1000ULL));
  proc_stats.cpu_usages.push_back(new_cpu_usage);

  auto cpu_usage_max_it = std::max_element(proc_stats.cpu_usages.begin(),
                                           proc_stats.cpu_usages.end());

  proc_stats.cpu_peak_usage =
      cpu_usage_max_it != proc_stats.cpu_usages.end() ? *cpu_usage_max_it : -1;

  proc_stats.generation = current_generation_;
  proc_stats.cpu_time = total_cpu_time;
  proc_stats.process_start_time = process_start_time;
}

void ProcessesStats::cleanupProcessStats() {
  std::lock_guard<std::mutex> process_stats_lock_guard(process_stats_lock_);

  for (auto proc_it = processes_stats_states_.begin();
       proc_it != processes_stats_states_.end();) {
    if (proc_it->second.generation < current_generation_) {
      proc_it = processes_stats_states_.erase(proc_it);
    } else {
      ++proc_it;
    }
  }
}

void ProcessesStats::increaseGeneration() {
  ++current_generation_;
}
} // namespace osquery
