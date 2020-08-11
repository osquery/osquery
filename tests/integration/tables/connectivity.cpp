/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for connectivity
// Spec file: specs/windows/connectivity.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class connectivity : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(connectivity, test_sanity) {
  auto const data = execute_query("select * from connectivity");

  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"disconnected", IntType},
      {"ipv4_no_traffic", IntType},
      {"ipv6_no_traffic", IntType},
      {"ipv4_subnet", IntType},
      {"ipv4_local_network", IntType},
      {"ipv4_internet", IntType},
      {"ipv6_subnet", IntType},
      {"ipv6_local_network", IntType},
      {"ipv6_internet", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
