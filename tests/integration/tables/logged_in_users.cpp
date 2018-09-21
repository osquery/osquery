
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for logged_in_users
// Spec file: specs/logged_in_users.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class LoggedInUsersTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(LoggedInUsersTest, sanity) {
  auto const rows = execute_query("select * from logged_in_users");
  auto const row_map = ValidatatioMap{
      {"type", NonEmptyString},
      {"user", NormalType},
      {"tty", NormalType},
      {"host", NormalType},
      {"time", NonNegativeInt},
      {"pid", NonNegativeInt},
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
