/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/io/quoted.hpp>

#include "osquery/numeric_monitoring/pre_aggregation_cache.h"
#include <osquery/logger/logger.h>

namespace osquery {

namespace monitoring {

Point::Point(std::string path,
             ValueType value,
             PreAggregationType pre_aggregation_type,
             TimePoint time_point)
    : path_(std::move(path)),
      value_(std::move(value)),
      pre_aggregation_type_(std::move(pre_aggregation_type)),
      time_point_(std::move(time_point)) {}

bool Point::tryToAggregate(const Point& new_point) {
  if (path_ != new_point.path_) {
    LOG(WARNING) << "Pre-aggregation is not possible as point paths are not "
                    "equal, previous path "
                 << boost::io::quoted(path_) << ", new path "
                 << boost::io::quoted(new_point.path_);

    return false;
  }
  if (pre_aggregation_type_ != new_point.pre_aggregation_type_) {
    LOG(WARNING) << "Pre-aggregation is not possible as PreAggregationType "
                    "types are not equal, previous type is "
                 << boost::io::quoted(to<std::string>(pre_aggregation_type_))
                 << ", new one is "
                 << boost::io::quoted(
                        to<std::string>(new_point.pre_aggregation_type_));
    return false;
  }
  time_point_ = std::max(time_point_, new_point.time_point_);
  switch (pre_aggregation_type_) {
  case PreAggregationType::None:
  case PreAggregationType::Avg:
  case PreAggregationType::Stddev:
  case PreAggregationType::P10:
  case PreAggregationType::P50:
  case PreAggregationType::P95:
  case PreAggregationType::P99:
    return false;
  case PreAggregationType::Sum:
    value_ = value_ + new_point.value_;
    break;
  case PreAggregationType::Min:
    value_ = std::min(value_, new_point.value_);
    break;
  case PreAggregationType::Max:
    value_ = std::max(value_, new_point.value_);
    break;
  case PreAggregationType::InvalidTypeUpperLimit:
    // nothing to do, the type is invalid
    LOG(ERROR) << "Invalid Pre-aggregation type "
               << boost::io::quoted(to<std::string>(pre_aggregation_type_));
    return false;
  }
  return true;
}

void PreAggregationCache::addPoint(Point point) {
  auto previous_index = points_index_.find(point.path_);
  if (previous_index == points_index_.end()) {
    points_index_.emplace(point.path_, points_.size());
    points_.push_back(std::move(point));
  } else {
    auto& previous = points_[previous_index->second];
    if (!previous.tryToAggregate(point)) {
      points_index_[point.path_] = points_.size();
      points_.push_back(std::move(point));
    }
  }
}

std::vector<Point> PreAggregationCache::takePoints() {
  auto taken_points = std::vector<Point>{};
  std::swap(taken_points, points_);
  points_index_.clear();
  return taken_points;
}

} // namespace monitoring
} // namespace osquery
