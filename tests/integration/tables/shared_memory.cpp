
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for shared_memory
// Spec file: specs/linux/shared_memory.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class sharedMemory : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(sharedMemory, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from shared_memory");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"shmid", IntType}
  //      {"owner_uid", IntType}
  //      {"creator_uid", IntType}
  //      {"pid", IntType}
  //      {"creator_pid", IntType}
  //      {"atime", IntType}
  //      {"dtime", IntType}
  //      {"ctime", IntType}
  //      {"permissions", NormalType}
  //      {"size", IntType}
  //      {"attached", IntType}
  //      {"status", NormalType}
  //      {"locked", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
