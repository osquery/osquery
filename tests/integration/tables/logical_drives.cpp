/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
  auto const data = execute_query("select * from logical_drives");
  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"device_id", NormalType},
      {"type", NormalType},
      {"description", NormalType},
      {"free_space", IntType},
      {"size", IntType},
      {"file_system", NormalType},
      {"boot_partition", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
