/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/tests/test_utils.h>
#include <osquery/tests/integration/tables/helper.h>
#include <string>

#include <iostream>

namespace osquery {
namespace table_tests {
class PrefetchTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(PrefetchTest, test_sanity) {
  // auto test = getTestConfigDirectory();
  // std::cout << test.string() << std::endl;
  std::string pf_config_tests = test + "\\windows\\prefetch\\%.pf'";
  std::string first_query =
      "select * from prefetch where path like '" + pf_config_tests;
  QueryData const rows = execute_query(first_query);
  std::string second_query =
      first_query +
      " AND last_execution_time = 1620953788 AND count = 3 AND "
      "number_of_accessed_files=53";
  QueryData const specific_rows = execute_query(second_query);
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
  if (!rows.empty()) {
    ASSERT_GT(rows.size(), 0ul);
    validate_rows(rows, row_map);
  }

  if (!specific_rows.empty()) {
    ASSERT_EQ(specific_rows.size(), 1ul);
    validate_rows(specific_rows, row_map);
  }

  // If running tests locally try local Prefetch files
  QueryData const default_rows = execute_query("select * from prefetch");
  if (!default_rows.empty()) {
    ASSERT_GT(default_rows.size(), 0ul);
    validate_rows(default_rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery
