
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for file
// Spec file: specs/utility/file.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class file : public IntegrationTableTest {};

TEST_F(file, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from file");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"path", NormalType}
  //      {"directory", NormalType}
  //      {"filename", NormalType}
  //      {"inode", IntType}
  //      {"uid", IntType}
  //      {"gid", IntType}
  //      {"mode", NormalType}
  //      {"device", IntType}
  //      {"size", IntType}
  //      {"block_size", IntType}
  //      {"atime", IntType}
  //      {"mtime", IntType}
  //      {"ctime", IntType}
  //      {"btime", IntType}
  //      {"hard_links", IntType}
  //      {"symlink", IntType}
  //      {"type", NormalType}
  //      {"attributes", NormalType}
  //      {"volume_serial", NormalType}
  //      {"file_id", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace osquery
