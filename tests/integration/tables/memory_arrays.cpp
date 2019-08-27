
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for memory_arrays
// Spec file: specs/posix/memory_arrays.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class memoryArrays : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(memoryArrays, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from memory_arrays");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"handle", NormalType}
  //      {"location", NormalType}
  //      {"use", NormalType}
  //      {"memory_error_correction", NormalType}
  //      {"max_capacity", IntType}
  //      {"memory_error_info_handle", NormalType}
  //      {"number_memory_devices", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
