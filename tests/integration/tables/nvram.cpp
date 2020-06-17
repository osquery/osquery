/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for nvram
// Spec file: specs/darwin/nvram.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class NvramTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(NvramTest, test_sanity) {
  auto const data = execute_query("select * from nvram");
  ASSERT_GT(data.size(), 0ul);
  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"type", NonEmptyString},
      {"value", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
