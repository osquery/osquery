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
class BamTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(BamTest, test_sanity) {
  QueryData const rows =
      execute_query("select * from background_activities_moderator");
  ASSERT_GT(rows.size(), 0ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"last_execution_time", NormalType},
      {"sid", NonEmptyString},
  };
  if (!rows.empty()) {
    validate_rows(rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery
