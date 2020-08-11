/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for kernel_modules
// Spec file: specs/linux/kernel_modules.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class KernelModules : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(KernelModules, test_sanity) {
  QueryData data = execute_query("select * from kernel_modules");
  ASSERT_GT(data.size(), 0ul);
  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"size", NonNegativeInt},
      {"used_by", NonEmptyString},
      {"status", NonEmptyString},
      {"address", NonNegativeInt},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
