
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for processes
// Spec file: specs/processes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class processes : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(processes, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from processes");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"pid", IntType}
  //      {"name", NormalType}
  //      {"path", NormalType}
  //      {"cmdline", NormalType}
  //      {"state", NormalType}
  //      {"cwd", NormalType}
  //      {"root", NormalType}
  //      {"uid", IntType}
  //      {"gid", IntType}
  //      {"euid", IntType}
  //      {"egid", IntType}
  //      {"suid", IntType}
  //      {"sgid", IntType}
  //      {"on_disk", IntType}
  //      {"wired_size", IntType}
  //      {"resident_size", IntType}
  //      {"total_size", IntType}
  //      {"user_time", IntType}
  //      {"system_time", IntType}
  //      {"disk_bytes_read", IntType}
  //      {"disk_bytes_written", IntType}
  //      {"start_time", IntType}
  //      {"parent", IntType}
  //      {"pgroup", IntType}
  //      {"threads", IntType}
  //      {"nice", IntType}
  //      {"is_elevated_token", IntType}
  //      {"upid", IntType}
  //      {"uppid", IntType}
  //      {"cpu_type", IntType}
  //      {"cpu_subtype", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
