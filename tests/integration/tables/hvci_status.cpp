/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Integration test for hvci_status
// Spec file: specs/windows/hvci_status.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class HVCIStatus : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(HVCIStatus, test_sanity) {
  QueryData data = execute_query("select * from hvci_status");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"version", NonEmptyString},
      {"instance_identifier", NormalType},
      {"vbs_status", NonEmptyString},
      {"code_integrity_policy_enforcement_status", NonEmptyString},
      {"umci_policy_status", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
