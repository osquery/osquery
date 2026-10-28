/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "system.h"

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/system.h>

#include <psapi.h>

#include <vector>

namespace osquery {
std::string getHostname() {
  DWORD size = 0;
  if (0 == GetComputerNameW(nullptr, &size)) {
    std::vector<WCHAR> computer_name(size, 0);
    GetComputerNameW(computer_name.data(), &size);
    return wstringToString(computer_name.data());
  }

  return {};
}

std::string getFqdn() {
  DWORD size = 0;
  if (0 == GetComputerNameExW(ComputerNameDnsFullyQualified, nullptr, &size)) {
    std::vector<WCHAR> fqdn(size, 0);
    GetComputerNameExW(ComputerNameDnsFullyQualified, fqdn.data(), &size);
    return wstringToString(fqdn.data());
  }

  return {};
}

bool getSelfResourceUsage(SelfResourceUsage& usage) {
  // Same sources and conversions as the processes table.
  auto proc = GetCurrentProcess();
  FILETIME create_time, exit_time, kernel_time, user_time;
  if (GetProcessTimes(
          proc, &create_time, &exit_time, &kernel_time, &user_time) == FALSE) {
    return false;
  }
  ULARGE_INTEGER time;
  time.HighPart = user_time.dwHighDateTime;
  time.LowPart = user_time.dwLowDateTime;
  usage.user_time_ms = time.QuadPart / 10000;
  time.HighPart = kernel_time.dwHighDateTime;
  time.LowPart = kernel_time.dwLowDateTime;
  usage.system_time_ms = time.QuadPart / 10000;

  PROCESS_MEMORY_COUNTERS_EX mem_ctr;
  if (GetProcessMemoryInfo(proc,
                           reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&mem_ctr),
                           sizeof(mem_ctr)) == FALSE) {
    return false;
  }
  usage.resident_size = mem_ctr.WorkingSetSize;
  return true;
}

} // namespace osquery
