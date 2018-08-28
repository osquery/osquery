
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for memory_arrays
// Spec file: specs/posix/memory_arrays.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class memoryArrays : public IntegrationTableTest {};

TEST_F(memoryArrays, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from memory_arrays");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
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
  // EXPECT_TRUE(validate_rows(data, row_map));
}

} // namespace osquery
