/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for file_events
// Spec file: specs/posix/file_events.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class fileEvents : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(fileEvents, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from file_events");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
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
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
