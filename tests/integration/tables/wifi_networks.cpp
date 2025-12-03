/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for wifi_networks
// Spec file: specs/darwin/wifi_networks.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class wifiNetworks : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(wifiNetworks, test_sanity) {
  auto const data = execute_query(
      "select *, last_connected, passpoint, roaming, auto_login, disabled "
      "from wifi_networks");
  if (data.empty()) {
    LOG(WARNING) << "Empty results of query from 'wifi_networks', assume there "
                    "are no wifi networks on the system";
    return;
  }

  ValidationMap row_map = {
      {"ssid", NormalType},
      {"network_name", NormalType},
      {"security_type", NormalType},
      {"last_connected", IntOrEmpty},
      {"last_connected_automatic", IntOrEmpty},
      {"last_connected_manual", IntOrEmpty},
      {"passpoint", IntOrEmpty},
      {"possibly_hidden", IntOrEmpty},
      {"roaming", IntOrEmpty},
      {"roaming_profile", NormalType},
      {"auto_login", IntOrEmpty},
      {"temporarily_disabled", IntOrEmpty},
      {"disabled", IntOrEmpty},
      {"add_reason", NormalType},
      {"added_at", IntOrEmpty},
      {"captive_portal", IntOrEmpty},
      {"captive_login_date", IntOrEmpty},
      {"was_captive_network", IntOrEmpty},
      {"auto_join", IntOrEmpty},
      {"personal_hotspot", IntOrEmpty},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
