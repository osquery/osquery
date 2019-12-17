/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for asl
// Spec file: specs/darwin/asl.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class asl : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(asl, test_sanity) {
  ValidationMap row_map = {
      {"time", IntType},
      {"time_nano_sec", IntType},
      {"host", NormalType},
      {"sender", NormalType},
      {"facility", NormalType},
      {"pid", IntType},
      {"gid", IntType},
      {"uid", IntType},
      {"level", IntType},
      {"message", NormalType},
      {"ref_pid", IntOrEmpty},
      {"ref_proc", NormalType},
      {"extra", NormalType},
  };

  auto const data = execute_query("select * from asl limit 1");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
