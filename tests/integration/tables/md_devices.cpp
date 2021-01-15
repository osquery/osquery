/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for md_devices
// Spec file: specs/linux/md_devices.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class mdDevices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(mdDevices, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from md_devices");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"device_name", NormalType}
  //      {"status", NormalType}
  //      {"raid_level", IntType}
  //      {"size", IntType}
  //      {"chunk_size", IntType}
  //      {"raid_disks", IntType}
  //      {"nr_raid_disks", IntType}
  //      {"working_disks", IntType}
  //      {"active_disks", IntType}
  //      {"failed_disks", IntType}
  //      {"spare_disks", IntType}
  //      {"superblock_state", NormalType}
  //      {"superblock_version", NormalType}
  //      {"superblock_update_time", IntType}
  //      {"bitmap_on_mem", NormalType}
  //      {"bitmap_chunk_size", NormalType}
  //      {"bitmap_external_file", NormalType}
  //      {"recovery_progress", NormalType}
  //      {"recovery_finish", NormalType}
  //      {"recovery_speed", NormalType}
  //      {"resync_progress", NormalType}
  //      {"resync_finish", NormalType}
  //      {"resync_speed", NormalType}
  //      {"reshape_progress", NormalType}
  //      {"reshape_finish", NormalType}
  //      {"reshape_speed", NormalType}
  //      {"check_array_progress", NormalType}
  //      {"check_array_finish", NormalType}
  //      {"check_array_speed", NormalType}
  //      {"unused_devices", NormalType}
  //      {"other", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
