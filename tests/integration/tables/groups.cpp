/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for groups
// Spec file: specs/groups.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {
namespace {

class groups : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(groups, test_sanity) {
  // Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  ValidatatioMap row_map = {
      {"gid", IntType},
      {"gid_signed", IntType},
      {"groupname", NormalType},
  };

  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("is_hidden", IntType);
  }

  // select * case
  auto const rows = execute_query("select * from groups");
  ASSERT_GE(rows.size(), 1ul);
  validate_rows(rows, row_map);

  // select with a specific gid
  auto test_gid = rows.front().at("gid").c_str();
  char query_string[50];
  sprintf(query_string, "select * from groups where gid=%s", test_gid);
  auto const rows_one = execute_query(query_string);
  ASSERT_GE(rows_one.size(), 1ul);
  validate_rows(rows_one, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
