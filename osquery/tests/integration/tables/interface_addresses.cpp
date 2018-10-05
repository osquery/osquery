
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for interface_addresses
// Spec file: specs/interface_addresses.table

#include <unordered_set>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class InterfaceAddressesTest : public IntegrationTableTest {};

TEST_F(InterfaceAddressesTest, sanity) {
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

} // namespace osquery
