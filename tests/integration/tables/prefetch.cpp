/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class PrefetchTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(PrefetchTest, test_sanity) {
  QueryData const rows = execute_query(
      "select * from prefetch where path like "
      "'D:"
      "\a\osquery\osquery\w\src\tools\tests\configs\windows\prefetch"
      "\\%.pf");
  QueryData const specific_rows = execute_query(
      "select * from prefetch where path like "
      "'D:"
      "\a\osquery\osquery\w\src\tools\tests\configs\windows\prefetch"
      "\%.pf AND last_execution_time = 1620953788 AND count = 3 AND "
      "number_of_accessed_files=53");
  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"number_of_accessed_directories", NormalType},
      {"filename", NormalType},
      {"accessed_files", NormalType},
      {"hash", NormalType},
      {"accessed_directories", NormalType},
      {"last_execution_time", NormalType},
      {"execution_times", NormalType},
      {"count", NormalType},
      {"size", NormalType},
      {"volume_serial", NormalType},
      {"volume_creation", NormalType},
      {"number_of_accessed_files", NormalType},
  };
  QueryData const default_rows = execute_query("select * from prefetch");
  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  ASSERT_EQ(specific_rows.size(), 1ul);
  validate_rows(specific_rows, row_map);

  if (!default_rows.empty()) {
    ASSERT_GT(rows.size(), 0ul);
    validate_rows(rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery
