/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for containerd_snapshots
// Spec file: specs/linux/containerd_snapshots.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class containerdSnapshots : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(containerdSnapshots, test_sanity) {
  auto const data = execute_query("select * from containerd_snapshots");
  // Needs a running containerd to produce rows; validate shape when present.
  ValidationMap row_map = {
      {"name", NormalType},
      {"namespace", NormalType},
      {"snapshotter", NormalType},
      {"parent", NormalType},
      {"kind", NormalType},
      {"created_at", NormalType},
      {"updated_at", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
