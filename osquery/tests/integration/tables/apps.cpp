
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for apps
// Spec file: specs/darwin/apps.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class apps : public IntegrationTableTest {};

TEST_F(apps, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from apps");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"name", NormalType}
  //      {"path", NormalType}
  //      {"bundle_executable", NormalType}
  //      {"bundle_identifier", NormalType}
  //      {"bundle_name", NormalType}
  //      {"bundle_short_version", NormalType}
  //      {"bundle_version", NormalType}
  //      {"bundle_package_type", NormalType}
  //      {"environment", NormalType}
  //      {"element", NormalType}
  //      {"compiler", NormalType}
  //      {"development_region", NormalType}
  //      {"display_name", NormalType}
  //      {"info_string", NormalType}
  //      {"minimum_system_version", NormalType}
  //      {"category", NormalType}
  //      {"applescript_enabled", NormalType}
  //      {"copyright", NormalType}
  //      {"last_opened_time", NormalType}
  //}
  // 4. Perform validation
  // EXPECT_TRUE(validate_rows(data, row_map));
}

} // namespace osquery
