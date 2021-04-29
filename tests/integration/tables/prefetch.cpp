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
  QueryData const rows = execute_query("select * from prefetch");
  if (!rows.empty()) {
    ASSERT_GT(rows.size(), 0ul);

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
    validate_rows(rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery
