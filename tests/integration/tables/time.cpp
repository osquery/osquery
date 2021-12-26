/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for time
// Spec file: specs/utility/time.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

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

  ValidationMap row_map = {
      {"weekday", NonEmptyString},
      {"year", IntType},
      {"month", IntMinMaxCheck(1, 12)},
      {"day", IntMinMaxCheck(1, 31)},
      {"hour", IntMinMaxCheck(0, 24)},
      {"minutes", IntMinMaxCheck(0, 59)},
      {"seconds", IntMinMaxCheck(0, 59)},
      {"timezone", NonEmptyString},
      {"local_timezone", NonEmptyString},
      {"unix_time", NonNegativeInt},
      {"timestamp", NonEmptyString},
      {"datetime", NonEmptyString},
      {"iso_8601", NonEmptyString},
  };
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("win_timestamp", NonNegativeInt);
  }
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
