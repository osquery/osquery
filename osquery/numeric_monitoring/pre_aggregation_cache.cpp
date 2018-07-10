/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/io/detail/quoted_manip.hpp>

#include "osquery/numeric_monitoring/pre_aggregation_cache.h"

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
    LOG(WARNING) << "Pre-aggregation is no possible, point paths is not equal. "
                    "That should not happen at all. Previous path is "
                 << boost::io::quoted(path_) << ", new one is "
                 << boost::io::quoted(new_point.path_);
    return false;
  }
  if (pre_aggregation_type_ != new_point.pre_aggregation_type_) {
    LOG(WARNING) << "Pre-aggregation is no possible, PreAggregationType type "
                    "missmatch. Previous type is "
                 << boost::io::quoted(to<std::string>(pre_aggregation_type_))
                 << ", new one is "
                 << boost::io::quoted(
                        to<std::string>(new_point.pre_aggregation_type_));
    return false;
  }
  time_point_ = std::max(time_point_, new_point.time_point_);
  switch (pre_aggregation_type_) {
  case PreAggregationType::None:
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
  auto previousIndex = points_intex_.find(point.path_);
  if (previousIndex == points_intex_.end()) {
    points_intex_.emplace(point.path_, points_.size());
    points_.push_back(std::move(point));
  } else {
    auto& previous = points_[previousIndex->second];
    if (!previous.tryToAggregate(point)) {
      points_intex_[point.path_] = points_.size();
      points_.push_back(std::move(point));
    }
  }
}

std::vector<Point> PreAggregationCache::takePoints() {
  auto taken_points = std::vector<Point>{};
  std::swap(taken_points, points_);
  points_intex_.clear();
  return taken_points;
}

} // namespace monitoring
} // namespace osquery
