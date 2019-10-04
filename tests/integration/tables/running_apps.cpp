
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for running_apps
// Spec file: specs/darwin/running_apps.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class runningApps : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(runningApps, test_sanity) {
  // 1. Query data
  QueryData general_query_data = execute_query("select * from running_apps");
  QueryData specific_query_data =
      execute_query("select * from running_apps where is_active = 1");
  // 2. Check size before validation
  ASSERT_GT(general_query_data.size(), 0ul);
  ASSERT_EQ(general_query_data[0].size(), 3ul);

  ASSERT_EQ(specific_query_data.size(), 1ul);
  ASSERT_EQ(specific_query_data[0].size(), 3ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  ValidatatioMap row_map = {{"pid", IntType},
                            {"bundle_identifier", NormalType},
                            {"is_active", IntType}};
  // 4. Perform validation
  validate_rows(general_query_data, row_map);
  validate_rows(specific_query_data, row_map);
}

} // namespace table_tests
} // namespace osquery
