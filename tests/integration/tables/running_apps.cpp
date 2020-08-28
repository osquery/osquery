/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
  ValidationMap row_map = {{"pid", IntType},
                           {"bundle_identifier", NormalType},
                           {"is_active", IntType}};

  QueryData general_query_data = execute_query("select * from running_apps");
  ASSERT_FALSE(general_query_data.empty());
  validate_rows(general_query_data, row_map);

  QueryData specific_query_data =
      execute_query("select * from running_apps where is_active = 1");
  ASSERT_EQ(specific_query_data.size(), 1ul);
  validate_rows(specific_query_data, row_map);
}

} // namespace table_tests
} // namespace osquery
