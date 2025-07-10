/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SystemProfilerTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SystemProfilerTest, test_system_profiler_no_constraints) {
  auto const data = execute_query("select * from system_profiler limit 10");
  ASSERT_EQ(data.size(), 0UL);
}

TEST_F(SystemProfilerTest, test_system_profiler_hardware_data) {
  auto const data = execute_query(
      "select * from system_profiler where data_type = 'SPHardwareDataType' "
      "limit 5");
  ASSERT_EQ(data.size(), 1UL);

  for (const auto& row : data) {
    EXPECT_EQ(row.at("data_type"), "SPHardwareDataType");
    EXPECT_FALSE(row.at("value").empty());
  }
}

TEST_F(SystemProfilerTest, test_system_profiler_in_clause) {
  auto const data = execute_query(
      "select * from system_profiler where data_type IN ('SPEthernetDataType', "
      "'SPFirewallDataType', 'SPMemoryDataType') limit 10");
  ASSERT_EQ(data.size(), 3UL);

  std::set<std::string> expected_types = {
      "SPEthernetDataType", "SPFirewallDataType", "SPMemoryDataType"};

  for (const auto& row : data) {
    EXPECT_TRUE(expected_types.find(row.at("data_type")) !=
                expected_types.end());
    EXPECT_FALSE(row.at("value").empty());
  }
}

} // namespace table_tests
} // namespace osquery