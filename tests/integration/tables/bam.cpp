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
class BamTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(BamTest, test_sanity) {
  QueryData const rows = execute_query("select * from bam");
  ASSERT_GT(rows.size(), 0ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"last_execution_time", NormalType},
      {"sid", NonEmptyString},
  };
  validate_rows(rows, row_map);
}
} // namespace table_tests
} // namespace osquery
