
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for interface_details
// Spec file: specs/interface_details.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class interfaceDetails : public IntegrationTableTest {};

TEST_F(interfaceDetails, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from interface_details");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"interface", NormalType}
  //      {"mac", NormalType}
  //      {"type", IntType}
  //      {"mtu", IntType}
  //      {"metric", IntType}
  //      {"flags", IntType}
  //      {"ipackets", IntType}
  //      {"opackets", IntType}
  //      {"ibytes", IntType}
  //      {"obytes", IntType}
  //      {"ierrors", IntType}
  //      {"oerrors", IntType}
  //      {"idrops", IntType}
  //      {"odrops", IntType}
  //      {"collisions", IntType}
  //      {"last_change", IntType}
  //      {"link_speed", IntType}
  //      {"pci_slot", NormalType}
  //      {"friendly_name", NormalType}
  //      {"description", NormalType}
  //      {"manufacturer", NormalType}
  //      {"connection_id", NormalType}
  //      {"connection_status", NormalType}
  //      {"enabled", IntType}
  //      {"physical_adapter", IntType}
  //      {"speed", IntType}
  //      {"service", NormalType}
  //      {"dhcp_enabled", IntType}
  //      {"dhcp_lease_expires", NormalType}
  //      {"dhcp_lease_obtained", NormalType}
  //      {"dhcp_server", NormalType}
  //      {"dns_domain", NormalType}
  //      {"dns_domain_suffix_search_order", NormalType}
  //      {"dns_host_name", NormalType}
  //      {"dns_server_search_order", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace osquery
