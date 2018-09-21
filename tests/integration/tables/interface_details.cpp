
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
namespace table_tests {

class InterfaceDetailsTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(InterfaceDetailsTest, sanity) {
  QueryData const rows = execute_query("select * from interface_details");
  auto const row_map = ValidatatioMap{
      {"interface", NonEmptyString},
      {"mac", NonEmptyString},
      {"type", NonNegativeInt},
      {"mtu", NonNegativeInt},
      {"metric", NonNegativeInt},
      {"flags", NonNegativeInt},
      {"ipackets", NonNegativeInt},
      {"opackets", NonNegativeInt},
      {"ibytes", NonNegativeInt},
      {"obytes", NonNegativeInt},
      {"ierrors", NonNegativeInt},
      {"oerrors", NonNegativeInt},
      {"idrops", NonNegativeInt},
      {"odrops", NonNegativeInt},
      {"collisions", NonNegativeInt},
      {"last_change", IntType},
#ifdef OSQUERY_POSIX
      {"link_speed", NonNegativeInt},
#endif
#ifdef OSQUERY_LINUX
      {"pci_slot", NormalType},
#endif
#ifdef OSQUERY_WINDOWS
      {"friendly_name", NormalType},
      {"description", NormalType},
      {"manufacturer", NormalType},
      {"connection_id", NormalType},
      {"connection_status", IntType},
      {"enabled", Bool},
      {"physical_adapter", Bool},
      {"speed", NonNegativeInt},
      {"service", NormalType},
      {"dhcp_enabled", Bool},
      {"dhcp_lease_expires", NormalType},
      {"dhcp_lease_obtained", NormalType},
      {"dhcp_server", NormalType},
      {"dns_domain", NormalType},
      {"dns_domain_suffix_search_order", NormalType},
      {"dns_host_name", NormalType},
      {"dns_server_search_order", NormalType},
#endif
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
