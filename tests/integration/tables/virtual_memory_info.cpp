/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for virtual_memory_info
// Spec file: specs/darwin/virtual_memory_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class virtualMemoryInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(virtualMemoryInfo, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from virtual_memory_info");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"free", IntType}
  //      {"active", IntType}
  //      {"inactive", IntType}
  //      {"speculative", IntType}
  //      {"throttled", IntType}
  //      {"wired", IntType}
  //      {"purgeable", IntType}
  //      {"faults", IntType}
  //      {"copy", IntType}
  //      {"zero_fill", IntType}
  //      {"reactivated", IntType}
  //      {"purged", IntType}
  //      {"file_backed", IntType}
  //      {"anonymous", IntType}
  //      {"uncompressed", IntType}
  //      {"compressor", IntType}
  //      {"decompressed", IntType}
  //      {"compressed", IntType}
  //      {"page_ins", IntType}
  //      {"page_outs", IntType}
  //      {"swap_ins", IntType}
  //      {"swap_outs", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
