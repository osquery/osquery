/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for sharing_preferences
// Spec file: specs/darwin/sharing_preferences.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class sharingPreferences : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(sharingPreferences, test_sanity) {
  ValidationMap row_map = {
      {"screen_sharing", Bool},
      {"file_sharing", Bool},
      {"printer_sharing", Bool},
      {"remote_login", Bool},
      {"remote_management", Bool},
      {"remote_apple_events", Bool},
      {"internet_sharing", Bool},
      {"bluetooth_sharing", Bool},
      {"disc_sharing", Bool},
      {"content_caching", Bool},
  };

  auto const data = execute_query("select * from sharing_preferences");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
