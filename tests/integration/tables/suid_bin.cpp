/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for suid_bin
// Spec file: specs/posix/suid_bin.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class suidBin : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(suidBin, test_sanity) {
  ValidationMap row_map = {
      {"path", NormalType},
      {"username", NormalType},
      {"groupname", NormalType},
      {"permissions", NormalType},
  };

  auto const data = execute_query("select * from suid_bin");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);

  auto const data_newgrp =
      execute_query("select * from suid_bin where path = '/usr/bin/newgrp'");
  ASSERT_FALSE(data_newgrp.empty());
  validate_rows(data_newgrp, row_map);
}

} // namespace table_tests
} // namespace osquery
