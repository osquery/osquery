/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for docker_container_networks
// Spec file: specs/posix/docker_container_networks.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class dockerContainerNetworks : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(dockerContainerNetworks, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from docker_container_networks");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"id", NormalType}
  //      {"name", NormalType}
  //      {"network_id", NormalType}
  //      {"endpoint_id", NormalType}
  //      {"gateway", NormalType}
  //      {"ip_address", NormalType}
  //      {"ip_prefix_len", IntType}
  //      {"ipv6_gateway", NormalType}
  //      {"ipv6_address", NormalType}
  //      {"ipv6_prefix_len", IntType}
  //      {"mac_address", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
