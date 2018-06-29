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

namespace osquery {

namespace monitoring {

/**
 * Types for clock and time point in monitoring plugin
 */
using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

using ValueType = double;

/**
 * @brief Record new point to numeric monitoring system.
 *
 * @param path A unique key in monitoring system. If you need to add some common
 * prefix for all osquery points do it in the plugin code.
 * @param value A numeric value of new point.
 * @param timePoint A time of new point, in vast majority of cases it is just
 * a now time (default time).
 *
 * Common way to use it:
 * @code{.cpp}
 * monitoring::record("path.for.your.point", value);
 * @endcode
 */
void record(const std::string& path,
            ValueType value,
            TimePoint timePoint = Clock::now());

} // namespace monitoring

} // namespace osquery
