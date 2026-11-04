/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for containerd_snapshot_labels
// Spec file: specs/linux/containerd_snapshot_labels.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class containerdSnapshotLabels : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(containerdSnapshotLabels, test_sanity) {
  auto const data = execute_query("select * from containerd_snapshot_labels");
  // Needs a running containerd to produce rows; validate shape when present.
  ValidationMap row_map = {
      {"name", NormalType},
      {"namespace", NormalType},
      {"snapshotter", NormalType},
      {"key", NormalType},
      {"value", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
