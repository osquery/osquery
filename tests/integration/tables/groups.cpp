/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
  ValidationMap row_map = {
      {"gid", IntType},
      {"gid_signed", IntType},
      {"groupname", NormalType},
  };

  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("is_hidden", IntType);
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("comment", NormalType);
    row_map.emplace("group_sid", NormalType);
  }

  // select * case
  auto const rows = execute_query("select * from groups");
  ASSERT_GE(rows.size(), 1ul);
  validate_rows(rows, row_map);

  // select with a specific gid
  auto test_gid = rows.front().at("gid");
  auto const rows_one =
      execute_query(std::string("select * from groups where gid=") + test_gid);
  ASSERT_GE(rows_one.size(), 1ul);
  validate_rows(rows_one, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
