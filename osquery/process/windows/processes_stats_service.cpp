/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <set>
#include <string>
#include <thread>

#include <Windows.h>

#include <Psapi.h>
#include <TlHelp32.h>

#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/process/processes_stats_service.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {

DECLARE_uint32(processes_stats_interval);
DECLARE_bool(processes_stats_worker_only);

constexpr std::uint64_t kTicksToMsRatio = 10000;

namespace {
void updateStatsForProcess(ProcessesStats& processes_stats,
                           DWORD pid,
                           HANDLE proc_handle) {
  FILETIME create_time;
  FILETIME exit_time;
  FILETIME kernel_time;
  FILETIME user_time;

  auto ret = GetProcessTimes(
      proc_handle, &create_time, &exit_time, &kernel_time, &user_time);

  if (ret == FALSE) {
    VLOG(1) << "Failed to lookup time data for process with pid " << pid
            << ", error code " << GetLastError();
    return;
  }

  auto user_time_total = filetimeToTicks(user_time) / kTicksToMsRatio;
  auto system_time_total = filetimeToTicks(kernel_time) / kTicksToMsRatio;
  auto process_start_time = filetimeToTicks(create_time) / kTicksToMsRatio;

  auto total_cpu_time = user_time_total + system_time_total;

  processes_stats.updateProcessStats(
      pid, total_cpu_time, process_start_time, FLAGS_processes_stats_interval);
}
} // namespace

ProcessesStatsService::ProcessesStatsService(
    std::shared_ptr<ProcessesStats> processes_stats)
    : InternalRunnable("ProcessesStatsService"),
      processes_stats_(processes_stats) {}

void ProcessesStatsService::start() {
  VLOG(1) << "ProcessesStatsService started";

  static auto worker_pid = PlatformProcess::getCurrentPid();

  while (!interrupted()) {
    if (FLAGS_processes_stats_worker_only) {
      auto proc_handle =
          OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, worker_pid);

      if (proc_handle == nullptr) {
        LOG(ERROR)
            << "Cannot open process handle of the worker process with pid "
            << worker_pid << ", error code " << GetLastError();
        pause(std::chrono::seconds(FLAGS_processes_stats_interval));
        continue;
      }

      updateStatsForProcess(*processes_stats_, worker_pid, proc_handle);
      CloseHandle(proc_handle);

    } else {
      auto proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
      auto const proc_snap_manager =
          scope_guard::create([&proc_snap]() { CloseHandle(proc_snap); });
      if (proc_snap == INVALID_HANDLE_VALUE) {
        LOG(ERROR) << "Failed to create snapshot of processes with "
                   << std::to_string(GetLastError());
        pause(std::chrono::seconds(FLAGS_processes_stats_interval));
        continue;
      }

      PROCESSENTRY32W proc;
      proc.dwSize = sizeof(PROCESSENTRY32W);

      auto ret = Process32FirstW(proc_snap, &proc);
      if (ret == FALSE) {
        LOG(ERROR) << "Failed to acquire first process information with "
                   << std::to_string(GetLastError());
        pause(std::chrono::seconds(FLAGS_processes_stats_interval));
        continue;
      }

      while (ret != FALSE) {
        // Ignore the System Idle Process
        if (proc.th32ProcessID == 0) {
          ret = Process32NextW(proc_snap, &proc);
          continue;
        }

        auto proc_handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.th32ProcessID);

        if (proc_handle == nullptr) {
          VLOG(1) << "Cannot open process handle of " << proc.th32ProcessID
                  << ", error code " << GetLastError();
          ret = Process32NextW(proc_snap, &proc);
          continue;
        }

        updateStatsForProcess(
            *processes_stats_, GetProcessId(proc_handle), proc_handle);

        CloseHandle(proc_handle);
        ret = Process32NextW(proc_snap, &proc);
      }

      auto error_code = GetLastError();
      if (error_code != ERROR_NO_MORE_FILES) {
        LOG(ERROR) << "Interrupted the update loop of the processes stats, "
                      "error code: "
                   << error_code;
      }

      processes_stats_->cleanupProcessStats();
      processes_stats_->increaseGeneration();
    }

    pause(std::chrono::seconds(FLAGS_processes_stats_interval));
  }
}
} // namespace osquery
