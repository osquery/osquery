/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for docker_container_stats
// Spec file: specs/posix/docker_container_stats.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class dockerContainerStats : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(dockerContainerStats, test_sanity) {
  // 1. Query data
  auto const data =
      execute_query("select * from docker_container_stats where id = ''");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"id", NormalType}
  //      {"name", NormalType}
  //      {"pids", IntType}
  //      {"read", IntType}
  //      {"preread", IntType}
  //      {"interval", IntType}
  //      {"disk_read", IntType}
  //      {"disk_write", IntType}
  //      {"num_procs", IntType}
  //      {"cpu_total_usage", IntType}
  //      {"cpu_kernelmode_usage", IntType}
  //      {"cpu_usermode_usage", IntType}
  //      {"system_cpu_usage", IntType}
  //      {"online_cpus", IntType}
  //      {"pre_cpu_total_usage", IntType}
  //      {"pre_cpu_kernelmode_usage", IntType}
  //      {"pre_cpu_usermode_usage", IntType}
  //      {"pre_system_cpu_usage", IntType}
  //      {"pre_online_cpus", IntType}
  //      {"memory_usage", IntType}
  //      {"memory_max_usage", IntType}
  //      {"memory_limit", IntType}
  //      {"network_rx_bytes", IntType}
  //      {"network_tx_bytes", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
