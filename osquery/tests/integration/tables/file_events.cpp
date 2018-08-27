
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for file_events
// Spec file: specs/posix/file_events.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class fileEvents : public IntegrationTableTest {};

TEST_F(fileEvents, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from file_events");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"target_path", NormalType}
  //      {"category", NormalType}
  //      {"action", NormalType}
  //      {"transaction_id", IntType}
  //      {"inode", IntType}
  //      {"uid", IntType}
  //      {"gid", IntType}
  //      {"mode", NormalType}
  //      {"size", IntType}
  //      {"atime", IntType}
  //      {"mtime", IntType}
  //      {"ctime", IntType}
  //      {"md5", NormalType}
  //      {"sha1", NormalType}
  //      {"sha256", NormalType}
  //      {"hashed", IntType}
  //      {"time", IntType}
  //      {"eid", NormalType}
  //}
  // 4. Perform validation
  // EXPECT_TRUE(validate_rows(data, row_map));
}

} // namespace osquery
