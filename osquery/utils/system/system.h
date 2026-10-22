/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <string>

#ifdef OSQUERY_WINDOWS
#include <osquery/utils/system/windows/system.h>
#elif OSQUERY_POSIX
#include <osquery/utils/system/posix/system.h>
#endif

namespace osquery {
/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
/**
 * @brief CPU time and memory of the calling process.
 *
 * The fields use the units of the processes table: milliseconds for the CPU
 * times and bytes for the resident set size.
 */
struct SelfResourceUsage {
  std::uint64_t user_time_ms{0};
  std::uint64_t system_time_ms{0};
  std::uint64_t resident_size{0};
};

/// Read the calling process' resource usage without a table query.
bool getSelfResourceUsage(SelfResourceUsage& usage);

std::string getHostname();

/**
 * @brief Getter for a host's fully qualified domain name
 *
 * @return a string representation of the hosts fully qualified domain name
 * if the host is joined to a domain, otherwise it simply returns the hostname
 */
std::string getFqdn();
} // namespace osquery
