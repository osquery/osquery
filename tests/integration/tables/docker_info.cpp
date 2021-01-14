/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for docker_info
// Spec file: specs/posix/docker_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class dockerInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(dockerInfo, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from docker_info");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"id", NormalType}
  //      {"containers", IntType}
  //      {"containers_running", IntType}
  //      {"containers_paused", IntType}
  //      {"containers_stopped", IntType}
  //      {"images", IntType}
  //      {"storage_driver", NormalType}
  //      {"memory_limit", IntType}
  //      {"swap_limit", IntType}
  //      {"kernel_memory", IntType}
  //      {"cpu_cfs_period", IntType}
  //      {"cpu_cfs_quota", IntType}
  //      {"cpu_shares", IntType}
  //      {"cpu_set", IntType}
  //      {"ipv4_forwarding", IntType}
  //      {"bridge_nf_iptables", IntType}
  //      {"bridge_nf_ip6tables", IntType}
  //      {"oom_kill_disable", IntType}
  //      {"logging_driver", NormalType}
  //      {"cgroup_driver", NormalType}
  //      {"kernel_version", NormalType}
  //      {"os", NormalType}
  //      {"os_type", NormalType}
  //      {"architecture", NormalType}
  //      {"cpus", IntType}
  //      {"memory", IntType}
  //      {"http_proxy", NormalType}
  //      {"https_proxy", NormalType}
  //      {"no_proxy", NormalType}
  //      {"name", NormalType}
  //      {"server_version", NormalType}
  //      {"root_dir", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
