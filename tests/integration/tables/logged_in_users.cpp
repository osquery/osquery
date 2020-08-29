/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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

TEST_F(LoggedInUsersTest, test_sanity) {
  auto const rows = execute_query("select * from logged_in_users");
  auto const row_map = ValidationMap{
      {"type", NonEmptyString},
      {"user", NormalType},
      {"tty", NormalType},
      {"host", NormalType},
      {"time", NonNegativeInt},
      {"pid", NonNegativeOrErrorInt},
#ifdef OSQUERY_WINDOWS
      {"sid", NormalType},
      {"registry_hive", NormalType},
#endif
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
