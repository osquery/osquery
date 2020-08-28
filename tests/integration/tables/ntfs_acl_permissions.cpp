/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for ntfs_acl_permissions
// Spec file: specs/windows/ntfs_acl_permissions.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ntfsAclPermissions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ntfsAclPermissions, test_sanity) {
  ValidationMap row_map = {
      {"path", NormalType},
      {"type", NormalType},
      {"principal", NormalType},
      {"access", NormalType},
      {"inherited_from", NormalType},
  };

  auto const data =
      execute_query("select * from ntfs_acl_permissions where path = 'C:\\'");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
