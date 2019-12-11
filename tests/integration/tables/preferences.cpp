/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
      "USING(username) where preferences.domain = 'com.apple.Preferences';");
  ASSERT_FALSE(datajoin.empty());
  validate_rows(datajoin, row_map);
}

} // namespace table_tests
} // namespace osquery
