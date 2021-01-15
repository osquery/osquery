/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for smart_drive_info
// Spec file: specs/smart/smart_drive_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class smartDriveInfo : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(smartDriveInfo, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from smart_drive_info");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"device_name", NormalType}
  //      {"disk_id", IntType}
  //      {"driver_type", NormalType}
  //      {"model_family", NormalType}
  //      {"device_model", NormalType}
  //      {"serial_number", NormalType}
  //      {"lu_wwn_device_id", NormalType}
  //      {"additional_product_id", NormalType}
  //      {"firmware_version", NormalType}
  //      {"user_capacity", NormalType}
  //      {"sector_sizes", NormalType}
  //      {"rotation_rate", NormalType}
  //      {"form_factor", NormalType}
  //      {"in_smartctl_db", IntType}
  //      {"ata_version", NormalType}
  //      {"transport_type", NormalType}
  //      {"sata_version", NormalType}
  //      {"read_device_identity_failure", NormalType}
  //      {"smart_supported", NormalType}
  //      {"smart_enabled", NormalType}
  //      {"packet_device_type", NormalType}
  //      {"power_mode", NormalType}
  //      {"warnings", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
