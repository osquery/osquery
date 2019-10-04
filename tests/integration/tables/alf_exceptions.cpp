/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for alf_exceptions
// Spec file: specs/darwin/alf_exceptions.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class alfExceptions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(alfExceptions, test_sanity) {
  auto const data = execute_query("select * from alf_exceptions");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NormalType},
      {"state", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
