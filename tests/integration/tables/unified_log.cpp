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
class UnifiedLogTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(UnifiedLogTest, test_sanity) {
  QueryData const rows =
      execute_query("select * from unified_log where pid > 100 and pid < 105");

  ASSERT_GT(rows.size(), 0ul);

  ValidationMap row_map = {
      {"timestamp", IntType},
      {"level", NormalType},
      {"storage", IntType},
      {"message", NormalType},
      {"activity", IntType},
      {"process", NormalType},
      {"pid", IntType},
      {"sender", NormalType},
      {"tid", IntType},
      {"category", NormalType},
      {"subsystem", NormalType},
  };
  validate_rows(rows, row_map);
}
} // namespace table_tests
} // namespace osquery
