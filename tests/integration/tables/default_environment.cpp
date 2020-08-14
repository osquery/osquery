/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for default_environment
// Spec file: specs/windows/default_environment.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class defaultEnvironment : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(defaultEnvironment, test_sanity) {
  auto const data = execute_query("select * from default_environment");

  ASSERT_GE(data.size(), 0ul);

  ValidationMap row_map = {
      {"variable", NonEmptyString},
      {"value", NormalType},
      {"expand", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
