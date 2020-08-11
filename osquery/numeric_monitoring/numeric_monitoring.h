/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>
#include <string>

#include "osquery/utils/conversions/tryto.h"
#include <osquery/utils/expected/expected.h>

namespace osquery {

namespace monitoring {

struct RecordKeys {
  std::string path;
  std::string value;
  std::string timestamp;
  std::string pre_aggregation;
  std::string sync;
};

struct HostIdentifierKeys {
  std::string name;
  std::string scheme;
};

const HostIdentifierKeys& hostIdentifierKeys();

const RecordKeys& recordKeys();

const char* registryName();

/**
 * Types for clock and time point in monitoring plugin
 */
using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

using ValueType = long long int;

enum class PreAggregationType {
  None,
  Sum,
  Min,
  Max,
  Avg,
  Stddev,
  P10, // Estimates 10th percentile
  P50, // Estimates 50th percentile
  P95, // Estimates 95th percentile
  P99, // Estimates 99th percentile
  // not existing PreAggregationType, upper limit definition
  InvalidTypeUpperLimit,
};

/**
 * @brief Record new point to numeric monitoring system.
 *
 * @param path A unique key in monitoring system. If you need to add some common
 * prefix for all osquery points do it in the plugin code.
 * @param value A numeric value of new point.
 * @param pre_aggregation An preliminary aggregation type for this particular
 * path @see PreAggregationType. It allows some numeric monitoring plugins
 * pre-aggregate points before send it.
 * @param sync when true pushes record without any buffering. This value is also
 * propagated to the plugin, so call to the plugin only returns once record is
 * sent.
 * @param time_point A time of new point, in vast majority of cases it is just
 * a now time (default time).
 *
 * Common way to use it:
 * @code{.cpp}
 * monitoring::record("watched.parameter.path",
 *                    10.42,
 *                    monitoring::PreAggregationType::Sum);
 * @endcode
 */
void record(const std::string& path,
            ValueType value,
            PreAggregationType pre_aggregation = PreAggregationType::None,
            const bool sync = false,
            TimePoint time_point = Clock::now());

/**
 * Force flush the pre-aggregation buffer.
 * Please use it, only when it's totally necessary.
 */
void flush();

}; // namespace monitoring

/**
 * Generic to convert PreAggregationType to string
 */
template <typename ToType>
typename std::enable_if<std::is_same<std::string, ToType>::value, ToType>::type
to(const monitoring::PreAggregationType& from);

/**
 * Generic to parse PreAggregationType from string
 */
template <typename ToType>
typename std::enable_if<
    std::is_same<monitoring::PreAggregationType, ToType>::value,
    Expected<ToType, ConversionError>>::type
tryTo(const std::string& from);

} // namespace osquery
