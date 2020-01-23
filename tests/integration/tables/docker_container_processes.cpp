
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for docker_container_processes
// Spec file: specs/posix/docker_container_processes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class dockerContainerProcesses : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(dockerContainerProcesses, test_sanity) {
  // 1. Query data
  auto const data =
      execute_query("select * from docker_container_processes where id = ''");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"id", NormalType}
  //      {"pid", IntType}
  //      {"name", NormalType}
  //      {"cmdline", NormalType}
  //      {"state", NormalType}
  //      {"uid", IntType}
  //      {"gid", IntType}
  //      {"euid", IntType}
  //      {"egid", IntType}
  //      {"suid", IntType}
  //      {"sgid", IntType}
  //      {"wired_size", IntType}
  //      {"resident_size", IntType}
  //      {"total_size", IntType}
  //      {"start_time", IntType}
  //      {"parent", IntType}
  //      {"pgroup", IntType}
  //      {"threads", IntType}
  //      {"nice", IntType}
  //      {"user", NormalType}
  //      {"time", NormalType}
  //      {"cpu", NormalType}
  //      {"mem", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
