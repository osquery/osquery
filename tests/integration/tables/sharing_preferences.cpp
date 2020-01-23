
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
  // 1. Query data
  auto const data = execute_query("select * from sharing_preferences");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"screen_sharing", IntType}
  //      {"file_sharing", IntType}
  //      {"printer_sharing", IntType}
  //      {"remote_login", IntType}
  //      {"remote_management", IntType}
  //      {"remote_apple_events", IntType}
  //      {"internet_sharing", IntType}
  //      {"bluetooth_sharing", IntType}
  //      {"disc_sharing", IntType}
  //      {"content_caching", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
