/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace osquery {

/**
 * @brief performance statistics about a query
 */
struct QueryPerformance {
  /// Number of executions.
  std::size_t executions{0};

  /// Last UNIX time in seconds the query was executed successfully.
  std::uint64_t last_executed{0};

  /// Total wall time taken in seconds
  std::uint64_t wall_time{0};

  /// Total wall time taken in milliseconds
  std::uint64_t wall_time_ms{0};

  /// Wall time in milliseconds of the latest execution
  std::uint64_t last_wall_time_ms{0};

  /// Total user time in milliseconds
  std::uint64_t user_time{0};

  /// User time in milliseconds of the latest execution
  std::uint64_t last_user_time{0};

  /// Total system time in milliseconds
  std::uint64_t system_time{0};

  /// System time in milliseconds of the latest execution
  std::uint64_t last_system_time{0};

  /// Average of the bytes of resident memory left allocated
  /// after collecting results
  std::uint64_t average_memory{0};

  /// Resident memory in bytes left allocated after collecting results
  /// of the latest execution
  std::uint64_t last_memory{0};

  /// Total bytes for the query
  std::uint64_t output_size{0};
};

} // namespace osquery
