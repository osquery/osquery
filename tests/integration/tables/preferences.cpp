/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for preferences
// Spec file: specs/darwin/preferences.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class preferences : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(preferences, test_sanity) {
  ValidationMap row_map = {
      {"domain", NormalType},
      {"key", NormalType},
      {"subkey", NormalType},
      {"value", NormalType},
      {"forced", IntType},
      {"username", NormalType},
      {"host", NormalType},
  };

  auto const data = execute_query("select * from preferences");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);

  auto const datajoin = execute_query(
      "select users.username, preferences.* from users CROSS JOIN preferences "
      "USING(username) where preferences.domain LIKE 'com.apple.%';");
  ASSERT_FALSE(datajoin.empty());
  validate_rows(datajoin, row_map);
}

} // namespace table_tests
} // namespace osquery
