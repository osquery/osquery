/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for block_devices
// Spec file: specs/posix/block_devices.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class blockDevices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(blockDevices, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from block_devices");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"name", NormalType}
  //      {"parent", NormalType}
  //      {"vendor", NormalType}
  //      {"model", NormalType}
  //      {"serial", NormalType}
  //      {"size", IntType}
  //      {"block_size", IntType}
  //      {"uuid", NormalType}
  //      {"type", NormalType}
  //      {"label", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
