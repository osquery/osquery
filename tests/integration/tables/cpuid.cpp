/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for cpuid
// Spec file: specs/cpuid.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class cpuid : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(cpuid, test_sanity) {
  ValidationMap row_map = {
      {"feature", NormalType},
      {"value", NormalType},
      {"output_register", NormalType},
      {"output_bit", IntType},
      {"input_eax", NormalType},
  };

  auto const data = execute_query("select * from cpuid");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
