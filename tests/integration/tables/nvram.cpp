/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
      {"value", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
