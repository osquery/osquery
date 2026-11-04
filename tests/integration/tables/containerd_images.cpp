/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for containerd_images
// Spec file: specs/linux/containerd_images.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class containerdImages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(containerdImages, test_sanity) {
  auto const data = execute_query("select * from containerd_images");
  // Needs a running containerd to produce rows; validate shape when present.
  ValidationMap row_map = {
      {"name", NormalType},
      {"namespace", NormalType},
      {"digest", NormalType},
      {"size", NormalType},
      {"media_type", NormalType},
      {"created_at", NormalType},
      {"updated_at", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
