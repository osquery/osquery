
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

// Sanity check integration test for disk_info
// Spec file: specs/windows/disk_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class diskInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(diskInfo, test_sanity) {
  auto const data = execute_query("select * from default_environment");

  ASSERT_GE(data.size(), 0ul);

  ValidatatioMap row_map = {
      {"variable", NormalType},
      {"value", NormalType},
      {"expand", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
