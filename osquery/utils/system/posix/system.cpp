/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "system.h"

#include <netdb.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <osquery/utils/system/system.h>

#include <boost/algorithm/string.hpp>

#ifdef __APPLE__
#include <libproc.h>
#include <mach/mach_time.h>
#elif defined(__linux__)
#include <fstream>
#include <unistd.h>
#endif

namespace osquery {
std::string getHostname() {
  /* POSIX states that the maximum amount of bytes for a hostname is 255 bytes
     though gethostname includes the null terminator too in the size. */
  std::size_t max_size = 256;

  std::vector<char> hostname(max_size, 0);
  gethostname(hostname.data(), max_size);

  std::string hostname_string(hostname.data());
  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string getFqdn() {
  std::string fqdn_string = getHostname();

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_CANONNAME;

  struct addrinfo* res = nullptr;
  if (getaddrinfo(fqdn_string.c_str(), nullptr, &hints, &res) == 0) {
    if (res->ai_canonname != nullptr) {
      fqdn_string = res->ai_canonname;
    }
  }
  if (res != nullptr) {
    freeaddrinfo(res);
  }

  return fqdn_string;
}

bool getSelfResourceUsage(SelfResourceUsage& usage) {
#ifdef __APPLE__
  // Same source and conversions as the processes table.
  struct rusage_info_v2 info;
  if (proc_pid_rusage(getpid(), RUSAGE_INFO_V2, (rusage_info_t*)&info) != 0) {
    return false;
  }
  static mach_timebase_info_data_t time_base;
  if (time_base.denom == 0) {
    mach_timebase_info(&time_base);
  }
  const std::uint64_t ns_per_ms = 1000000;
  usage.user_time_ms =
      ((info.ri_user_time * time_base.numer) / time_base.denom) / ns_per_ms;
  usage.system_time_ms =
      ((info.ri_system_time * time_base.numer) / time_base.denom) / ns_per_ms;
  usage.resident_size = info.ri_resident_size;
  return true;
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) != 0) {
    return false;
  }
  usage.user_time_ms = static_cast<std::uint64_t>(ru.ru_utime.tv_sec) * 1000 +
                       ru.ru_utime.tv_usec / 1000;
  usage.system_time_ms = static_cast<std::uint64_t>(ru.ru_stime.tv_sec) * 1000 +
                         ru.ru_stime.tv_usec / 1000;
#ifdef __linux__
  // /proc/self/statm: size resident shared text lib data dt, in pages.
  std::ifstream statm("/proc/self/statm");
  std::uint64_t size = 0, resident = 0;
  if (!(statm >> size >> resident)) {
    return false;
  }
  usage.resident_size = resident * static_cast<std::uint64_t>(getpagesize());
#else
  // No cheap current-RSS source; report the peak like ru_maxrss documents.
  usage.resident_size = static_cast<std::uint64_t>(ru.ru_maxrss) * 1024;
#endif
  return true;
#endif
}

} // namespace osquery
