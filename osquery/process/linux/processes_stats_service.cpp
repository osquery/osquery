/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <charconv>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>

#include <osquery/filesystem/linux/proc.h>
#include <osquery/process/process.h>
#include <osquery/process/processes_stats_service.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

DECLARE_uint32(processes_stats_interval);
DECLARE_bool(processes_stats_worker_only);

const int kMSIn1CLKTCK = (1000 / sysconf(_SC_CLK_TCK));
namespace {

void updateStatsForPids(ProcessesStats& processes_stats,
                        const std::set<std::string>& processes) {
  for (const auto& pid_str : processes) {
    std::string content;
    auto status = readFile("/proc/" + pid_str + "/stat", content);

    if (!status.ok()) {
      continue;
    }

    auto start = content.find_last_of(")");

    if (start == std::string::npos) {
      VLOG(1) << "Failed parse /proc/stat of pid " << pid_str;
    }

    auto details = vsplit(content.substr(start + 2), ' ');
    if (details.size() < 22) {
      VLOG(1) << "Invalid /proc/stat content";
      continue;
    }

    const auto& user_time_str = details[11];
    const auto& system_time_str = details[12];
    const auto& start_time_str = details[21];

    std::uint32_t user_time = 0;
    {
      auto [ptr, ec] = std::from_chars(
          user_time_str.begin(), user_time_str.end(), user_time);
      if (ec != std::errc()) {
        VLOG(1) << "Failed to convert the user time field " << user_time_str
                << " to a number, error: " << static_cast<int>(ec);
        continue;
      }
    }

    std::uint32_t system_time = 0;
    {
      auto [ptr, ec] = std::from_chars(
          system_time_str.begin(), system_time_str.end(), system_time);
      if (ec != std::errc()) {
        VLOG(1) << "Failed to convert the system time field " << system_time_str
                << " to a number, error: " << static_cast<int>(ec);
        continue;
      }
    }

    std::uint64_t start_time = 0;
    {
      auto [ptr, ec] = std::from_chars(
          start_time_str.begin(), start_time_str.end(), start_time);
      if (ec != std::errc()) {
        VLOG(1) << "Failed to convert the start time field " << start_time_str
                << " to a number, error: " << static_cast<int>(ec);
        continue;
      }
    }

    auto pid_exp = tryTo<std::uint32_t>(pid_str);
    if (pid_exp.isError()) {
      VLOG(1) << "Failed to convert the pid string " << pid_str
              << " to a number";
      continue;
    }

    auto total_cpu_time = (user_time + system_time) * kMSIn1CLKTCK;

    processes_stats.updateProcessStats(pid_exp.take(),
                                       total_cpu_time,
                                       start_time,
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

  static auto worker_pid = PlatformProcess::getCurrentPid();
  static auto worker_pid_str = std::to_string(worker_pid);

  while (!interrupted()) {
    if (FLAGS_processes_stats_worker_only) {
      updateStatsForPids(*processes_stats_, {worker_pid_str});
    } else {
      std::set<std::string> processes;
      auto status = osquery::procProcesses(processes);

      if (!status.ok()) {
        LOG(ERROR) << "Failed to list processes in /proc: "
                   << status.getMessage();
        pause(std::chrono::seconds(FLAGS_processes_stats_interval));
        continue;
      }

      updateStatsForPids(*processes_stats_, processes);
    }

    pause(std::chrono::seconds(FLAGS_processes_stats_interval));
  }
}
} // namespace osquery
