
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for interface_addresses
// Spec file: specs/interface_addresses.table

#include <unordered_set>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class InterfaceAddressesTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(InterfaceAddressesTest, test_sanity) {
  QueryData const rows = execute_query("select * from interface_addresses");

  auto const row_map = ValidatatioMap{
      {"interface", NonEmptyString},
      {"address", verifyIpAddress},
      {"mask", verifyIpAddress},
      {"broadcast", verifyEmptyStringOrIpAddress},
      {"point_to_point", verifyEmptyStringOrIpAddress},
      {"type",
       SpecificValuesCheck{"dhcp", "manual", "auto", "other", "unknown"}},
#ifdef OSQUERY_WINDOWS
      {"friendly_name", NormalType},
#endif
  };
  validate_rows(rows, row_map);
  auto addresses = std::unordered_set<std::string>{};
  for (auto const& row : rows) {
    addresses.insert(row.at("address"));
  }
  EXPECT_EQ(addresses.size(), rows.size())
      << "Addresses associated with interfaces must be unique";
}

} // namespace table_tests
} // namespace osquery
