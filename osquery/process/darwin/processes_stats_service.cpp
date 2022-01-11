/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <filesystem>
#include <set>
#include <string>
#include <thread>

#include <unistd.h>

#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/process/processes_stats_service.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/darwin/proc/proc.h>

namespace osquery {

DECLARE_uint32(processes_stats_interval);
DECLARE_bool(processes_stats_worker_only);

constexpr std::uint32_t kNsToMsRatio = 1000 * 1000;

namespace {
void updateStatsForPids(ProcessesStats& processes_stats,
                        const std::vector<pid_t>& processes,
                        const mach_timebase_info_data_t& time_base) {
  for (const auto& proc_pid : processes) {
    struct rusage_info_v0 rusage_info_data;
    int status =
        proc_pid_rusage(proc_pid,
                        RUSAGE_INFO_V0,
                        reinterpret_cast<rusage_info_t*>(&rusage_info_data));

    if (status != 0) {
      continue;
    }

    // time information
    auto total_cpu_time =
        (((rusage_info_data.ri_user_time + rusage_info_data.ri_system_time) *
          time_base.numer) /
         time_base.denom) /
        kNsToMsRatio;

    auto process_start_time = rusage_info_data.ri_proc_start_abstime;

    processes_stats.updateProcessStats(proc_pid,
                                       total_cpu_time,
                                       process_start_time,
                                       FLAGS_processes_stats_interval);
  }

  processes_stats.cleanupProcessStats();
  processes_stats.increaseGeneration();
}
} // namespace

ProcessesStatsService::ProcessesStatsService(
    std::shared_ptr<ProcessesStats> processes_stats)
    : InternalRunnable("ProcessesStatsService"),
      processes_stats_(processes_stats) {}

void ProcessesStatsService::start() {
  VLOG(1) << "ProcessesStatsService started";

  static mach_timebase_info_data_t time_base = []() {
    mach_timebase_info_data_t time_base;
    auto ret = mach_timebase_info(&time_base);
    if (ret != KERN_SUCCESS) {
      VLOG(1) << "Failed to get the timebase info";
      return mach_timebase_info_data_t{};
    }

    return time_base;
  }();

  if (time_base.denom == 0) {
    VLOG(1) << "Timebase denominator is 0; cannot properly convert time units";
    return;
  }

  static const auto worker_pid = PlatformProcess::getCurrentPid();

  while (!interrupted()) {
    if (FLAGS_processes_stats_worker_only) {
      updateStatsForPids(*processes_stats_, {worker_pid}, time_base);
    } else {
      auto opt_pids = osquery::procProcesses();

      if (!opt_pids.has_value()) {
        LOG(ERROR) << "Failed to get the running processes pids";
        pause(std::chrono::seconds(FLAGS_processes_stats_interval));
        continue;
      }

      updateStatsForPids(*processes_stats_, *opt_pids, time_base);
    }

    pause(std::chrono::seconds(FLAGS_processes_stats_interval));
  }
}
} // namespace osquery
