/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for sudoers
// Spec file: specs/posix/sudoers.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class Sudoers : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(Sudoers, test_sanity) {
  auto const data = execute_query("select * from sudoers");
  ValidationMap row_map = {
      {"source", NonEmptyString},
      {"header", NonEmptyString},
      {"rule_details", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
