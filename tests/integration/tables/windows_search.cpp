/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for connectivity
// Spec file: specs/windows/windows_search.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

namespace table_tests {

class windows_search : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(windows_search, test_sanity) {
  auto const data = execute_query("select * from windows_search where query = '*' and max_results = 1 and select_columns = 'system.size' and sort = 'system.size desc'");

  ValidationMap row_map = {
      {"path", NormalType},
      {"attribute", NormalType},
      {"value", NormalType},
      {"max_results", IntType},
      {"sort", NormalType},
      {"select_columns", NormalType},
      {"query", NormalType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
