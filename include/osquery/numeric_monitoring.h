/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <chrono>
#include <string>

#include <osquery/core/conversions.h>
#include <osquery/expected.h>

namespace osquery {

namespace monitoring {

/**
 * Types for clock and time point in monitoring plugin
 */
using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

using ValueType = long long int;

enum class AggregationType : unsigned {
  None,
  Sum,
  Min,
  Max,
};

/**
 * @brief Record new point to numeric monitoring system.
 *
 * @param path A unique key in monitoring system. If you need to add some common
 * prefix for all osquery points do it in the plugin code.
 * @param value A numeric value of new point.
 * @param aggr_type An aggregation type for this particular path @see
 * AggregationType. It allows some plugin pre-aggregate points before send it.
 * @param time_point A time of new point, in vast majority of cases it is just
 * a now time (default time).
 *
 * Common way to use it:
 * @code{.cpp}
 * monitoring::record("watched.parameter.path",
 *                    10.42,
 *                    monitoring::AggregationType::Sum);
 * @endcode
 */
void record(const std::string& path,
            ValueType value,
            AggregationType aggr_type = AggregationType::None,
            TimePoint time_point = Clock::now());

} // namespace monitoring

/**
 * Generic to convert AggregationType to string
 */
template <typename ToType>
typename std::enable_if<std::is_same<std::string, ToType>::value,
                        Expected<ToType, ConversionError>>::type
tryTo(const monitoring::AggregationType& from);

/**
 * Generic to parse AggregationType from string
 */
template <typename ToType>
typename std::enable_if<
    std::is_same<monitoring::AggregationType, ToType>::value,
    Expected<ToType, ConversionError>>::type
tryTo(const std::string& from);

} // namespace osquery
