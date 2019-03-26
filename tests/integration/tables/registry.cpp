
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for registry
// Spec file: specs/windows/registry.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
namespace {

class RegistryTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(RegistryTest, test_sanity) {
  QueryData const rows = execute_query("select * from registry");
  ASSERT_GT(rows.size(), 0ul);
  auto const row_map = ValidatatioMap{
      {"key", NonEmptyString},
      {"path", NonEmptyString},
      {"name", NonEmptyString},
      {"type", NonEmptyString},
      {"data", NormalType},
      {"mtime", NonNegativeInt},
  };
  validate_rows(rows, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
