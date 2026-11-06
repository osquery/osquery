/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for containerd_container_labels
// Spec file: specs/linux/containerd_container_labels.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class containerdContainerLabels : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(containerdContainerLabels, test_sanity) {
  auto const data = execute_query("select * from containerd_container_labels");
  // Needs a running containerd to produce rows; validate shape when present.
  ValidationMap row_map = {
      {"id", NormalType},
      {"namespace", NormalType},
      {"key", NormalType},
      {"value", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
