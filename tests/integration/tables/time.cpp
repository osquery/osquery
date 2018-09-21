/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for time
// Spec file: specs/utility/time.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class Time : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(Time, test_sanity) {
  QueryData data = execute_query("select * from time");

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
      {"weekday", NonEmptyString},
      {"year", IntType},
      {"month", IntMinMaxCheck(1, 12)},
      {"day", IntMinMaxCheck(1, 31)},
      {"hour", IntMinMaxCheck(0, 24)},
      {"minutes", IntMinMaxCheck(0, 59)},
      {"seconds", IntMinMaxCheck(0, 59)},
      {"timezone", NonEmptyString},
      {"local_time", NonNegativeInt},
      {"local_timezone", NonEmptyString},
      {"unix_time", NonNegativeInt},
      {"timestamp", NonEmptyString},
      {"datetime", NonEmptyString},
      {"iso_8601", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
