/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for carbon_black_info
// Spec file: specs/carbon_black_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class carbonBlackInfo : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(carbonBlackInfo, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from carbon_black_info");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"sensor_id", IntType}
  //      {"config_name", NormalType}
  //      {"collect_store_files", IntType}
  //      {"collect_module_loads", IntType}
  //      {"collect_module_info", IntType}
  //      {"collect_file_mods", IntType}
  //      {"collect_reg_mods", IntType}
  //      {"collect_net_conns", IntType}
  //      {"collect_processes", IntType}
  //      {"collect_cross_processes", IntType}
  //      {"collect_emet_events", IntType}
  //      {"collect_data_file_writes", IntType}
  //      {"collect_process_user_context", IntType}
  //      {"collect_sensor_operations", IntType}
  //      {"log_file_disk_quota_mb", IntType}
  //      {"log_file_disk_quota_percentage", IntType}
  //      {"protection_disabled", IntType}
  //      {"sensor_ip_addr", NormalType}
  //      {"sensor_backend_server", NormalType}
  //      {"event_queue", IntType}
  //      {"binary_queue", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
