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

class UptimeTests : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(UptimeTests, test_sanity) {
  QueryData data = execute_query("select * from uptime");
  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {{"days", NonNegativeInt},
                            {"hours", IntMinMaxCheck(0, 24)},
                            {"minutes", IntMinMaxCheck(0, 60)},
                            {"seconds", IntMinMaxCheck(0, 60)},
                            {"total_seconds", NonNegativeInt}};

  validate_rows(data, row_map);
}
} // namespace table_tests
} // namespace osquery
