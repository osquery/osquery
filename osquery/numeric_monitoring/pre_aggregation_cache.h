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

#include <unordered_map>

#include <osquery/numeric_monitoring.h>

namespace osquery {

namespace monitoring {

/**
 * Representation of smallest unit of monitoring system.
 * Consists of watched value itself, watching time, unique name for this set of
 * values and pre-aggregation type.
 */
class Point {
 public:
  /**
   * Constructor
   * Consists of watched value itself, watching time, unique name for this set
   * of values and pre-aggregation type.
   * @param path Path or in other words unique name for the sequence of
   * monitoring values
   * @param value Observed value
   * @param pre_aggregation_type Pre-aggregation type for the sequence
   * @param time_point Time point at which value was observed
   */
  explicit Point(std::string path,
                 ValueType value,
                 PreAggregationType pre_aggregation_type,
                 TimePoint time_point);

  bool tryToAggregate(const Point& new_point);

 public:
  std::string path_;
  ValueType value_;
  PreAggregationType pre_aggregation_type_;
  TimePoint time_point_;
};

class PreAggregationCache {
 public:
  explicit PreAggregationCache() = default;

  void addPoint(Point point);

  std::vector<Point> takePoints();

  std::size_t size() const noexcept {
    return points_.size();
  }

 private:
  std::unordered_map<std::string, std::size_t> points_intex_;
  std::vector<Point> points_;
};

} // namespace monitoring
} // namespace osquery
