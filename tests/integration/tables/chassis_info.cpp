/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for chassis_info
// Spec file: specs/windows/chassis_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class chassisTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(chassisTest, test_sanity) {
  const QueryData data = execute_query("select * from chassis_info");
  ASSERT_EQ(data.size(), 1ul);
  ValidationMap row_map = {
      {"audible_alarm", NonEmptyString},
      {"breach_description", NormalType},
      {"chassis_types", NonEmptyString},
      {"description", NormalType},
      {"lock", NonEmptyString},
      {"manufacturer", NormalType},
      {"model", NormalType},
      {"security_breach", NonEmptyString},
      {"serial", NormalType},
      {"smbios_tag", NormalType},
      {"sku", NormalType},
      {"status", NormalType},
      {"visible_alarm", NonEmptyString},
  };
  validate_rows(data, row_map);
}
} // namespace table_tests
} // namespace osquery
