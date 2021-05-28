/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/system/env.h>
#include <string>

namespace osquery {
namespace table_tests {
class PrefetchTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(PrefetchTest, test_sanity) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"filename", NormalType},
      {"hash", NormalType},
      {"last_execution_time", IntType},
      {"execution_times", NormalType},
      {"count", IntType},
      {"size", IntType},
      {"volume_serial", NormalType},
      {"volume_creation", NormalType},
      {"accessed_directories", NormalType},
      {"accessed_directories_count", IntType},
      {"accessed_files", NormalType},
      {"accessed_files_count", IntType},
  };

  std::string query = "select * from prefetch where path like '" + *test +
                      "\\windows\\prefetch\\%.pf'";
  QueryData const rows = execute_query(query);

  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  std::string second_query = query +
                             " AND last_execution_time = 1620953788 AND count "
                             "= 3 AND accessed_files_count = 53";
  QueryData const specific_rows = execute_query(second_query);

  ASSERT_EQ(specific_rows.size(), 1ul);
  validate_rows(specific_rows, row_map);

  // If running tests locally try local Prefetch files
  QueryData const default_rows = execute_query("select * from prefetch");
  if (!default_rows.empty()) {
    ASSERT_GT(default_rows.size(), 0ul);
    validate_rows(default_rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery
