/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for connectivity
// Spec file: specs/windows/windows_firewall_rules.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/tables/networking/windows/windows_firewall_rules.h>

namespace osquery {

namespace table_tests {

class windows_firewall_rules : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(windows_firewall_rules, test_sanity) {
  auto const data =
      execute_query("select * from windows_firewall_rules LIMIT 1");

  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"name", NormalType},
      {"app_name", NormalType},
      {"action", NormalType},
      {"enabled", IntType},
      {"grouping", NormalType},
      {"direction", NormalType},
      {"protocol", NormalType},
      {"local_addresses", NormalType},
      {"remote_addresses", NormalType},
      {"local_ports", NormalType},
      {"remote_ports", NormalType},
      {"icmp_types_codes", NormalType},
      {"profile_domain", IntType},
      {"profile_private", IntType},
      {"profile_public", IntType},
      {"service_name", NormalType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
