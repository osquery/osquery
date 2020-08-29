/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for nt_info
// Spec file: specs/windows/nt_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class NtDomains : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(NtDomains, test_sanity) {
  QueryData data = execute_query("select * from ntdomains");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"client_site_name", NormalType},
      {"dc_site_name", NormalType},
      {"dns_forest_name", NormalType},
      {"domain_controller_address", NormalType},
      {"domain_controller_name", NormalType},
      {"domain_name", NormalType},
      {"status", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
