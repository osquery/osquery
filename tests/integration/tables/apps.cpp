/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for apps
// Spec file: specs/darwin/apps.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class apps : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(apps, test_sanity) {
  ValidationMap row_map = {
      {"name", NormalType},
      {"path", NormalType},
      {"bundle_executable", NormalType},
      {"bundle_identifier", NormalType},
      {"bundle_name", NormalType},
      {"bundle_short_version", NormalType},
      {"bundle_version", NormalType},
      {"bundle_package_type", NormalType},
      {"environment", NormalType},
      {"element", NormalType},
      {"compiler", NormalType},
      {"development_region", NormalType},
      {"display_name", NormalType},
      {"info_string", NormalType},
      {"minimum_system_version", NormalType},
      {"category", NormalType},
      {"applescript_enabled", NormalType},
      {"copyright", NormalType},
      {"last_opened_time", NormalType},
  };

  auto const data = execute_query("select * from apps");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);

  // Not totally sure what apps we expect on the VMs used by CI.
  auto const data1 = execute_query(
      "select * from apps where path = '/Applications/Preview.app'");
  ASSERT_EQ(data1.size(), 1ul);
  validate_rows(data1, row_map);
}

} // namespace table_tests
} // namespace osquery
