/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for lldp_neighbors
// Spec file: specs/lldpd/lldp_neighbors.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class lldpNeighbors : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(lldpNeighbors, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from lldp_neighbors");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"interface", NormalType}
  //      {"rid", IntType}
  //      {"chassis_id_type", NormalType}
  //      {"chassis_id", NormalType}
  //      {"chassis_sysname", NormalType}
  //      {"chassis_sys_description", IntType}
  //      {"chassis_bridge_capability_available", IntType}
  //      {"chassis_bridge_capability_enabled", IntType}
  //      {"chassis_router_capability_available", IntType}
  //      {"chassis_router_capability_enabled", IntType}
  //      {"chassis_repeater_capability_available", IntType}
  //      {"chassis_repeater_capability_enabled", IntType}
  //      {"chassis_wlan_capability_available", IntType}
  //      {"chassis_wlan_capability_enabled", IntType}
  //      {"chassis_tel_capability_available", IntType}
  //      {"chassis_tel_capability_enabled", IntType}
  //      {"chassis_docsis_capability_available", IntType}
  //      {"chassis_docsis_capability_enabled", IntType}
  //      {"chassis_station_capability_available", IntType}
  //      {"chassis_station_capability_enabled", IntType}
  //      {"chassis_other_capability_available", IntType}
  //      {"chassis_other_capability_enabled", IntType}
  //      {"chassis_mgmt_ips", NormalType}
  //      {"port_id_type", NormalType}
  //      {"port_id", NormalType}
  //      {"port_description", NormalType}
  //      {"port_ttl", IntType}
  //      {"port_mfs", IntType}
  //      {"port_aggregation_id", NormalType}
  //      {"port_autoneg_supported", IntType}
  //      {"port_autoneg_enabled", IntType}
  //      {"port_mau_type", NormalType}
  //      {"port_autoneg_10baset_hd_enabled", IntType}
  //      {"port_autoneg_10baset_fd_enabled", IntType}
  //      {"port_autoneg_100basetx_hd_enabled", IntType}
  //      {"port_autoneg_100basetx_fd_enabled", IntType}
  //      {"port_autoneg_100baset2_hd_enabled", IntType}
  //      {"port_autoneg_100baset2_fd_enabled", IntType}
  //      {"port_autoneg_100baset4_hd_enabled", IntType}
  //      {"port_autoneg_100baset4_fd_enabled", IntType}
  //      {"port_autoneg_1000basex_hd_enabled", IntType}
  //      {"port_autoneg_1000basex_fd_enabled", IntType}
  //      {"port_autoneg_1000baset_hd_enabled", IntType}
  //      {"port_autoneg_1000baset_fd_enabled", IntType}
  //      {"power_device_type", NormalType}
  //      {"power_mdi_supported", IntType}
  //      {"power_mdi_enabled", IntType}
  //      {"power_paircontrol_enabled", IntType}
  //      {"power_pairs", NormalType}
  //      {"power_class", NormalType}
  //      {"power_8023at_enabled", IntType}
  //      {"power_8023at_power_type", NormalType}
  //      {"power_8023at_power_source", NormalType}
  //      {"power_8023at_power_priority", NormalType}
  //      {"power_8023at_power_allocated", NormalType}
  //      {"power_8023at_power_requested", NormalType}
  //      {"med_device_type", NormalType}
  //      {"med_capability_capabilities", IntType}
  //      {"med_capability_policy", IntType}
  //      {"med_capability_location", IntType}
  //      {"med_capability_mdi_pse", IntType}
  //      {"med_capability_mdi_pd", IntType}
  //      {"med_capability_inventory", IntType}
  //      {"med_policies", NormalType}
  //      {"vlans", NormalType}
  //      {"pvid", NormalType}
  //      {"ppvids_supported", NormalType}
  //      {"ppvids_enabled", NormalType}
  //      {"pids", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
