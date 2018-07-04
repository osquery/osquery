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

#include <osquery/numeric_monitoring.h>

namespace osquery {

namespace monitoring {

class Point {
 public:
  explicit Point(
    ValueType value
    , AggregationType aggr_type
    , TimePoint time_point
  )
    : value_(std::move(value))
    , aggr_type_(std::move(aggr_type))
    , time_point_(std::move(time_point))
  {
  }

  bool update(
    const Point& new_point
  ) {
    if (aggr_type_ != new_point.aggr_type_) {
      LOG(ERROR) << "Aggregation type missmatch: previous point type is "
        << tryTo<std::string>(aggr_type_)
        << ", new point type is "
        << tryTo<std::string>(new_point.aggr_type_);
      return false;
    }
    switch (aggr_type_) {
      case AggregationType::None:
        return false;
      case AggregationType::Sum:
        value_ = value_ + new_point.value_;
        break;
      case AggregationType::Min:
        value_ = std::min(value_, new_point.value_);
        break;
      case AggregationType::Max:
        value_ = std::max(value_, new_point.value_);
        break;
    }
    return true;
  }

 public:
  std::string path_;
  ValueType value_;
  AggregationType aggr_type_;
  TimePoint time_point_;
};

class AggregationCache {
public:
  explicit AggregationCache() = default;

  void record(Point point) {
    auto previous = points_intex_.find(point.path_);
    if (previous == points_intex_.end()) {
      points_intex_.emplace(point.path_, points_.size());
      points_.push_back(std::move(point));
    } else {
      if (!previous->update(point)) {
        points_intex_[point.path_] = points_.size();
        points_.push_back(std::move(point));
      }
    }
  }

  std::vector<Point> takePoints() {
    auto taken_points = std::vector<Point>{};
    std::swap(taken_points, points_);
    points_intex_.clear();
    return taken_points;
  }

  std::size_t size() const noexcept {
    return points_.size();
  }

private:
  std::unordered_map<std::string, std::size_t> points_intex_;
  std::vector<Point> points_;
};

} // namespace monitoring
} // namespace osquery
