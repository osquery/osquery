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

class OfficeMruTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(OfficeMruTest, test_sanity) {
  QueryData const rows = execute_query("select * from office_mru");

  ValidationMap row_map = {{"application", NonEmptyString},
                           {"version", NonEmptyString},
                           {"path", NonEmptyString},
                           {"last_opened_time", NormalType},
                           {"sid", NonEmptyString}};
  if (!rows.empty()) {
    validate_rows(rows, row_map);
    ASSERT_GT(rows.size(), 0ul);
  }
}

} // namespace table_tests
} // namespace osquery
