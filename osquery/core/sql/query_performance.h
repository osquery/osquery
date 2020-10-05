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

namespace osquery {

/**
 * @brief performance statistics about a query
 */
struct QueryPerformance {
  /// Number of executions.
  size_t executions{0};

  /// Last UNIX time in seconds the query was executed successfully.
  unsigned long long int last_executed{0};

  /// Total wall time taken
  unsigned long long int wall_time{0};

  /// Total user time (cycles)
  unsigned long long int user_time{0};

  /// Total system time (cycles)
  unsigned long long int system_time{0};

  /// Average memory differentials. This should be near 0.
  unsigned long long int average_memory{0};
};

} // namespace osquery
