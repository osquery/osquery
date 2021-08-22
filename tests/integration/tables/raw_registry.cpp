/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for registry
// Spec file: specs/windows/registry.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
namespace {

class RawRegistryTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(RawRegistryTest, test_sanity) {
  QueryData const rows = execute_query("select *,physical_device from raw_registry where reg_path = 'C:\\Windows\\System32\\config\\SYSTEM'");
  ASSERT_GT(rows.size(), 0ul);
  auto const row_map = ValidationMap{
      {"key", NormalType},
      {"path", NormalType},
      {"name", NormalType},
      {"type", NormalType},
      {"data", NormalType},
      {"modified_time", NonNegativeInt},
      {"reg_path", NormalType},
      {"reg_file", NormalType},
      {"physical_device", NormalType},
  };
  validate_rows(rows, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
