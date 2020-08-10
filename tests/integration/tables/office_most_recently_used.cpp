/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class OfficeMostRecentlyUsedTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(OfficeMostRecentlyUsedTest, test_sanity) {
  QueryData const rows =
      execute_query("select * from office_most_recently_used");

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
