/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for process_open_files
// Spec file: specs/posix/process_open_files.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class ProcessOpenFilesTest : public IntegrationTableTest {};

TEST_F(ProcessOpenFilesTest, test_sanity) {
  QueryData data = execute_query("select * from process_open_files");
  ASSERT_GT(data.size(), 0ul);
  ValidatatioMap row_map = {
      {"pid", NonNegativeInt}, {"fd", NonNegativeInt}, {"path", FileOnDisk}};
  validate_rows(data, row_map);
}

} // namespace osquery
