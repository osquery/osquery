/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for physical_disk_performance
// Spec file: specs/windows/physical_disk_performance.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class physicalDiskPerformance : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(physicalDiskPerformance, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from physical_disk_performance");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"name", NormalType}
  //      {"avg_disk_bytes_per_read", IntType}
  //      {"avg_disk_bytes_per_write", IntType}
  //      {"avg_disk_read_queue_length", IntType}
  //      {"avg_disk_write_queue_length", IntType}
  //      {"avg_disk_sec_per_read", IntType}
  //      {"avg_disk_sec_per_write", IntType}
  //      {"current_disk_queue_length", IntType}
  //      {"percent_disk_read_time", IntType}
  //      {"percent_disk_write_time", IntType}
  //      {"percent_disk_time", IntType}
  //      {"percent_idle_time", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
