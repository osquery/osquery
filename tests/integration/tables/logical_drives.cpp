
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for logical_drives
// Spec file: specs/windows/logical_drives.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class logicalDrives : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(logicalDrives, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from logical_drives");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"device_id", NormalType}
  //      {"type", NormalType}
  //      {"free_space", IntType}
  //      {"size", IntType}
  //      {"file_system", NormalType}
  //      {"boot_partition", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
