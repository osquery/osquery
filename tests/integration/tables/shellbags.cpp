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
class ShellbagsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ShellbagsTest, test_sanity) {
  QueryData const rows = execute_query("select * from shellbags");
  if (!rows.empty()) {
    QueryData const specific_query_rows =
        execute_query("select * from shellbags where path like '%This PC%'");

    ASSERT_GT(rows.size(), 0ul);
    ASSERT_GT(specific_query_rows.size(), 0ul);
    ValidationMap row_map = {
        {"sid", NonEmptyString},
        {"source", NonEmptyString},
        {"path", NonEmptyString},
        {"modified_time", NormalType},
        {"created_time", NormalType},
        {"accessed_time", NormalType},
        {"mft_entry", NormalType},
        {"mft_sequence", NormalType},
    };
    validate_rows(rows, row_map);
    validate_rows(specific_query_rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery
