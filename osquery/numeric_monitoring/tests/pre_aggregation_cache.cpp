/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <limits>
#include <set>

#include <gtest/gtest.h>

#include <osquery/numeric_monitoring/pre_aggregation_cache.h>

namespace osquery {

GTEST_TEST(PreAggregationPoint, tryToUpdate_same_path_none) {
  const auto now = monitoring::Clock::now();
  const auto path = "test.path.to.nowhere/something";
  auto prev_pt =
      monitoring::Point(path, 1, monitoring::PreAggregationType::None, now);
  auto new_pt =
      monitoring::Point(path, 1, monitoring::PreAggregationType::None, now);
  ASSERT_FALSE(prev_pt.tryToAggregate(new_pt));
}

GTEST_TEST(PreAggregationPoint, tryToUpdate_same_path_different_types) {
  const std::set<monitoring::PreAggregationType> nonaggregatable = {
      monitoring::PreAggregationType::None,
      monitoring::PreAggregationType::Avg,
      monitoring::PreAggregationType::Stddev,
      monitoring::PreAggregationType::P10,
      monitoring::PreAggregationType::P50,
      monitoring::PreAggregationType::P95,
      monitoring::PreAggregationType::P99};
  const auto now = monitoring::Clock::now();
  const auto path = "test.path.to.nowhere/paranoid";
  using UnderType = std::underlying_type<monitoring::PreAggregationType>::type;
  const auto upper_limit = static_cast<UnderType>(
      monitoring::PreAggregationType::InvalidTypeUpperLimit);
  for (auto prev_ind = UnderType{}; prev_ind < upper_limit; ++prev_ind) {
    for (auto new_ind = UnderType{}; new_ind < upper_limit; ++new_ind) {
      auto prev_aggr = static_cast<monitoring::PreAggregationType>(prev_ind);
      auto prev_pt = monitoring::Point(path, 1, prev_aggr, now);
      auto new_aggr = static_cast<monitoring::PreAggregationType>(new_ind);
      auto new_pt = monitoring::Point(path, 1, new_aggr, now);
      if (new_aggr == prev_aggr &&
          nonaggregatable.find(new_aggr) == nonaggregatable.end()) {
        ASSERT_TRUE(prev_pt.tryToAggregate(new_pt));
      } else {
        ASSERT_FALSE(prev_pt.tryToAggregate(new_pt));
      }
    }
  }
}

GTEST_TEST(PreAggregationPoint, tryToUpdate_different_path_sum) {
  const auto now = monitoring::Clock::now();
  const auto prev_path = "test.path.to.nowhere/something";
  auto prev_pt =
      monitoring::Point(prev_path, 1, monitoring::PreAggregationType::Sum, now);
  const auto new_path = "test.path.to.nowhere/something.else";
  auto new_pt =
      monitoring::Point(new_path, 1, monitoring::PreAggregationType::Sum, now);
  ASSERT_FALSE(prev_pt.tryToAggregate(new_pt));
  ASSERT_FALSE(new_pt.tryToAggregate(prev_pt));
}

GTEST_TEST(PreAggregationPoint, tryToUpdate_sum) {
  const auto now = monitoring::Clock::now();
  const auto path = "test.path.to.nowhere";
  auto prev_pt =
      monitoring::Point(path, 399, monitoring::PreAggregationType::Sum, now);
  auto new_pt = monitoring::Point(path,
                                  -8,
                                  monitoring::PreAggregationType::Sum,
                                  now - std::chrono::seconds{2});
  ASSERT_TRUE(prev_pt.tryToAggregate(new_pt));
  EXPECT_EQ(now, prev_pt.time_point_);
  EXPECT_EQ(391, prev_pt.value_);
}

GTEST_TEST(PreAggregationPoint, tryToUpdate_min) {
  const auto now = monitoring::Clock::now();
  const auto path = "test.path.to.nowhere";
  auto prev_pt =
      monitoring::Point(path, 3, monitoring::PreAggregationType::Min, now);
  auto new_pt = monitoring::Point(path,
                                  8,
                                  monitoring::PreAggregationType::Min,
                                  now - std::chrono::seconds{2});
  ASSERT_TRUE(prev_pt.tryToAggregate(new_pt));
  EXPECT_EQ(now, prev_pt.time_point_);
  EXPECT_EQ(3, prev_pt.value_);
}

GTEST_TEST(PreAggregationPoint, tryToUpdate_max) {
  const auto now = monitoring::Clock::now();
  const auto path = "test.path.to.nowhere";
  auto prev_pt =
      monitoring::Point(path, 3, monitoring::PreAggregationType::Max, now);
  auto new_pt = monitoring::Point(path,
                                  42,
                                  monitoring::PreAggregationType::Max,
                                  now - std::chrono::hours{2});
  ASSERT_TRUE(prev_pt.tryToAggregate(new_pt));
  EXPECT_EQ(now, prev_pt.time_point_);
  EXPECT_EQ(42, prev_pt.value_);
}

GTEST_TEST(PreAggregationCache, life_cycle) {
  const auto now = monitoring::Clock::now();
  auto cache = monitoring::PreAggregationCache{};
  const auto none_path = "test.path.to.nowhere.none";
  ASSERT_EQ(0, cache.size());
  cache.addPoint(monitoring::Point(
      none_path, 1, monitoring::PreAggregationType::None, now));
  ASSERT_EQ(1, cache.size());
  cache.addPoint(monitoring::Point(
      none_path, 2, monitoring::PreAggregationType::None, now));
  ASSERT_EQ(2, cache.size());

  const auto sum_path = "test.path.to.nowhere.sum";
  cache.addPoint(monitoring::Point(sum_path,
                                   3,
                                   monitoring::PreAggregationType::Sum,
                                   now - std::chrono::seconds(1)));
  ASSERT_EQ(3, cache.size());
  cache.addPoint(monitoring::Point(
      sum_path, -1, monitoring::PreAggregationType::Sum, now));
  ASSERT_EQ(3, cache.size());

  const auto min_path = "test.path.to.nowhere.min";
  cache.addPoint(monitoring::Point(min_path,
                                   7,
                                   monitoring::PreAggregationType::Min,
                                   now - std::chrono::seconds(10)));
  ASSERT_EQ(4, cache.size());
  cache.addPoint(
      monitoring::Point(min_path,
                        std::numeric_limits<monitoring::ValueType>::max(),
                        monitoring::PreAggregationType::Min,
                        now));
  ASSERT_EQ(4, cache.size());
  cache.addPoint(
      monitoring::Point(min_path,
                        std::numeric_limits<monitoring::ValueType>::min(),
                        monitoring::PreAggregationType::Min,
                        now - std::chrono::seconds(1)));
  ASSERT_EQ(4, cache.size());

  const auto max_path = "test.path.to.nowhere.max";
  cache.addPoint(monitoring::Point(max_path,
                                   7,
                                   monitoring::PreAggregationType::Max,
                                   now - std::chrono::seconds(99)));
  ASSERT_EQ(5, cache.size());
  cache.addPoint(
      monitoring::Point(max_path,
                        std::numeric_limits<monitoring::ValueType>::max(),
                        monitoring::PreAggregationType::Max,
                        now - std::chrono::seconds(1)));
  ASSERT_EQ(5, cache.size());
  cache.addPoint(
      monitoring::Point(max_path,
                        std::numeric_limits<monitoring::ValueType>::min(),
                        monitoring::PreAggregationType::Max,
                        now - std::chrono::seconds(2)));
  ASSERT_EQ(5, cache.size());

  cache.addPoint(monitoring::Point(
      none_path, 6, monitoring::PreAggregationType::None, now));
  ASSERT_EQ(6, cache.size());

  auto points = cache.takePoints();
  EXPECT_EQ(0, cache.size());
  ASSERT_EQ(6, points.size());

  cache.addPoint(
      monitoring::Point(sum_path, 9, monitoring::PreAggregationType::Sum, now));
  EXPECT_EQ(1, cache.size());

  auto counters = std::unordered_map<std::string, std::size_t>{
      {none_path, 0},
      {sum_path, 0},
      {min_path, 0},
      {max_path, 0},
  };
  for (const auto& p : points) {
    ++counters.at(p.path_);
    if (p.pre_aggregation_type_ == monitoring::PreAggregationType::Sum) {
      EXPECT_EQ(2, p.value_);
      EXPECT_EQ(now, p.time_point_);
    } else if (p.pre_aggregation_type_ == monitoring::PreAggregationType::Min) {
      EXPECT_EQ(std::numeric_limits<monitoring::ValueType>::min(), p.value_);
      EXPECT_EQ(now, p.time_point_);
    } else if (p.pre_aggregation_type_ == monitoring::PreAggregationType::Max) {
      EXPECT_EQ(std::numeric_limits<monitoring::ValueType>::max(), p.value_);
      EXPECT_EQ(now - std::chrono::seconds(1), p.time_point_);
    }
  }
  EXPECT_EQ(3, counters[none_path]);
  EXPECT_EQ(1, counters[sum_path]);
  EXPECT_EQ(1, counters[min_path]);
  EXPECT_EQ(1, counters[max_path]);
}

} // namespace osquery
