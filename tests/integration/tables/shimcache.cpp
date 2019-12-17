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
class ShimcacheTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ShimcacheTest, test_sanity) {
  QueryData const rows = execute_query("select * from shimcache");
  QueryData const specific_query_rows =
      execute_query("select * from shimcache where path like '%.exe'");

  ASSERT_GT(rows.size(), 0ul);
  ASSERT_GT(specific_query_rows.size(), 0ul);

  ValidationMap row_map = {
      {"entry", NonEmptyString},
      {"path", NormalType},
      {"modified_time", NormalType},
      {"execution_flag", NormalType},
  };
  validate_rows(rows, row_map);
  validate_rows(specific_query_rows, row_map);
}
} // namespace table_tests
} // namespace osquery
