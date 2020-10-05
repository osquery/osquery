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

class UptimeTests : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(UptimeTests, test_sanity) {
  QueryData data = execute_query("select * from uptime");
  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {{"days", NonNegativeInt},
                           {"hours", IntMinMaxCheck(0, 24)},
                           {"minutes", IntMinMaxCheck(0, 60)},
                           {"seconds", IntMinMaxCheck(0, 60)},
                           {"total_seconds", NonNegativeInt}};

  validate_rows(data, row_map);
}
} // namespace table_tests
} // namespace osquery
