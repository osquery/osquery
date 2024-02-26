/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/core/sql/query_performance.h"
#include <gtest/gtest.h>

namespace osquery {

class QueryPerformanceTests : public testing::Test {};

TEST_F(QueryPerformanceTests, test_query_performance) {
  // Default case
  QueryPerformance defaultStats;
  auto emptyStats = QueryPerformance("");
  ASSERT_EQ(defaultStats, emptyStats);
  ASSERT_EQ("0,0,0,0,0,0,0,0,0,0,0,0", defaultStats.toCSV());

  // Normal case
  {
    QueryPerformance expected;
    expected.executions = 1;
    expected.last_executed = 2;
    expected.wall_time = 3;
    expected.wall_time_ms = 4;
    expected.last_wall_time_ms = 5;
    expected.user_time = 6;
    expected.last_user_time = 7;
    expected.system_time = 8;
    expected.last_system_time = 9;
    expected.average_memory = 10;
    expected.last_memory = 11;
    expected.output_size = 12;
    std::string csv = "1,2,3,4,5,6,7,8,9,10,11,12";
    auto filledStats = QueryPerformance(csv);
    ASSERT_EQ(expected, filledStats);
    ASSERT_EQ(csv, expected.toCSV());
    ASSERT_EQ(csv, filledStats.toCSV());
  }

  // Invalid case
  {
    std::string csv = "1,,bozo,4,5,6,7,8,9,10,11,12";
    auto filledStats = QueryPerformance(csv);
    ASSERT_EQ(0, filledStats.last_executed);
    ASSERT_EQ(0, filledStats.wall_time);
    ASSERT_EQ("1,0,0,4,5,6,7,8,9,10,11,12", filledStats.toCSV());
  }
}

} // namespace osquery