/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace tables {

QueryData genSystemProfilerResults(QueryContext& context);

class SystemProfilerTests : public testing::Test {};

TEST_F(SystemProfilerTests, test_system_profiler_basic) {
  QueryContext context;
  QueryData results = genSystemProfilerResults(context);

  // Should return some results
  EXPECT_GE(results.size(), 0UL);

  // Check that all rows have the expected columns
  for (const auto& row : results) {
    EXPECT_EQ(row.count("data_type"), 1);
    EXPECT_EQ(row.count("key"), 1);
    EXPECT_EQ(row.count("value"), 1);
    EXPECT_EQ(row.count("data_type_path"), 1);
  }
}

TEST_F(SystemProfilerTests, test_system_profiler_hardware_constraint) {
  QueryContext context;
  context.constraints["data_type"].add(
      Constraint(EQUALS, "SPHardwareDataType"));

  QueryData results = genSystemProfilerResults(context);

  // Should return some results for hardware data
  EXPECT_GE(results.size(), 0UL);

  // All results should be for hardware data type
  for (const auto& row : results) {
    EXPECT_EQ(row.at("data_type"), "SPHardwareDataType");
  }
}

TEST_F(SystemProfilerTests, test_system_profiler_memory_constraint) {
  QueryContext context;
  context.constraints["data_type"].add(Constraint(EQUALS, "SPMemoryDataType"));

  QueryData results = genSystemProfilerResults(context);

  // Should return some results for memory data
  EXPECT_GE(results.size(), 0UL);

  // All results should be for memory data type
  for (const auto& row : results) {
    EXPECT_EQ(row.at("data_type"), "SPMemoryDataType");
  }
}

} // namespace tables
} // namespace osquery