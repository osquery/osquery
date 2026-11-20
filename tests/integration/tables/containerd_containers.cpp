/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for containerd_containers
// Spec file: specs/linux/containerd_containers.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class containerdContainers : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(containerdContainers, test_sanity) {
  auto const data = execute_query("select * from containerd_containers");
  // Needs a running containerd to produce rows; validate shape when present.
  ValidationMap row_map = {
      {"id", NormalType},
      {"namespace", NormalType},
      {"name", NormalType},
      {"image", NormalType},
      {"snapshot_key", NormalType},
      {"runtime", NormalType},
      {"pid", NormalType},
      {"status", NormalType},
      {"created_at", NormalType},
      {"updated_at", NormalType},
      {"cgroup_namespace", NormalType},
      {"ipc_namespace", NormalType},
      {"mnt_namespace", NormalType},
      {"net_namespace", NormalType},
      {"pid_namespace", NormalType},
      {"user_namespace", NormalType},
      {"uts_namespace", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
