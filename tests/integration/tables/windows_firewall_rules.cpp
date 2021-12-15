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

namespace tables {
extern QueryData renderFirewallRules(const FirewallRules& rules);
}

namespace table_tests {

class windows_firewall_rules : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

namespace {
tables::FirewallRules generateTestRules() {
  tables::FirewallRules rules;
  tables::FirewallRule r = {
      "TestName",
      "TestAppName",
      NET_FW_ACTION_BLOCK,
      false,
      NET_FW_RULE_DIR_IN,
      NET_FW_IP_VERSION_V4,
      "",
      "",
      "",
      "",
      "",
      0,
  };

  tables::FirewallRule rule;
  rule = r;
  rules.push_back(rule);

  rule = r;
  r.action = NET_FW_ACTION_ALLOW;
  rules.push_back(rule);

  rule = r;
  r.enabled = true;
  rules.push_back(rule);

  rule = r;
  r.enabled = false;
  rules.push_back(rule);

  rule = r;
  r.direction = NET_FW_RULE_DIR_OUT;
  rules.push_back(rule);

  rule = r;
  r.protocol = NET_FW_IP_VERSION_V6;
  rules.push_back(rule);

  rule = r;
  r.protocol = NET_FW_IP_VERSION_ANY;
  rules.push_back(rule);

  rule = r;
  r.profileBitmask = NET_FW_PROFILE2_DOMAIN;
  rules.push_back(rule);

  rule = r;
  r.profileBitmask = NET_FW_PROFILE2_PUBLIC;
  rules.push_back(rule);

  rule = r;
  r.profileBitmask = NET_FW_PROFILE2_PRIVATE;
  rules.push_back(rule);

  rule = r;
  r.profileBitmask = NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PUBLIC;
  rules.push_back(rule);

  rule = r;
  r.profileBitmask = NET_FW_PROFILE2_PUBLIC | NET_FW_PROFILE2_PRIVATE;
  rules.push_back(rule);

  rule = r;
  r.localAddresses = "*";
  rules.push_back(rule);

  rule = r;
  r.remoteAddresses = "LocalSubnet";
  rules.push_back(rule);

  rule = r;
  r.localPorts = "*";
  rules.push_back(rule);

  rule = r;
  r.remotePorts = "*";
  rules.push_back(rule);

  rule = r;
  r.icmpTypesCodes = "8:*";
  rules.push_back(rule);
  return rules;
}

void validateRendered(const tables::FirewallRule& rule, Row& row) {
  ASSERT_EQ(rule.name, row["name"]);
  ASSERT_EQ(rule.appName, row["app_name"]);
  switch (rule.action) {
  case NET_FW_ACTION_BLOCK:
    ASSERT_EQ("Block", row["action"]);
    break;
  case NET_FW_ACTION_ALLOW:
    ASSERT_EQ("Allow", row["action"]);
    break;
  default:
    ASSERT_EQ("", row["action"]);
    break;
  }

  ASSERT_EQ(INTEGER(rule.enabled), row["enabled"]);

  switch (rule.direction) {
  case NET_FW_RULE_DIR_IN:
    ASSERT_EQ("In", row["direction"]);
    break;
  case NET_FW_RULE_DIR_OUT:
    ASSERT_EQ("Out", row["direction"]);
    break;
  default:
    ASSERT_EQ("", row["direction"]);
    break;
  }

  switch (rule.protocol) {
  case NET_FW_IP_PROTOCOL_TCP:
    ASSERT_EQ("TCP", row["protocol"]);
    break;
  case NET_FW_IP_PROTOCOL_UDP:
    ASSERT_EQ("UDP", row["protocol"]);
    break;
  case NET_FW_IP_PROTOCOL_ANY:
    ASSERT_EQ("Any", row["protocol"]);
    break;
  default:
    ASSERT_EQ("", row["protocol"]);
    break;
  }

  ASSERT_EQ(rule.localAddresses, row["local_addresses"]);
  ASSERT_EQ(rule.remoteAddresses, row["remote_addresses"]);
  ASSERT_EQ(rule.localPorts, row["local_ports"]);
  ASSERT_EQ(rule.remotePorts, row["remote_ports"]);
  ASSERT_EQ(rule.icmpTypesCodes, row["icmp_types_codes"]);

  ASSERT_EQ(INTEGER(bool(rule.profileBitmask & NET_FW_PROFILE2_DOMAIN)),
            row["profile_domain"]);
  ASSERT_EQ(INTEGER(bool(rule.profileBitmask & NET_FW_PROFILE2_PRIVATE)),
            row["profile_private"]);
  ASSERT_EQ(INTEGER(bool(rule.profileBitmask & NET_FW_PROFILE2_PUBLIC)),
            row["profile_public"]);
}

} // namespace

TEST_F(windows_firewall_rules, test_firewall_rules_render) {
  auto rules = generateTestRules();
  auto rows = renderFirewallRules(rules);

  ASSERT_EQ(rows.size(), rules.size());

  size_t i = 0;
  std::for_each(
      rules.cbegin(), rules.cend(), [&](const tables::FirewallRule& rule) {
        auto row = rows[i++];
        validateRendered(rule, row);
      });

  ValidationMap row_map = {
      {"name", NormalType},
      {"app_name", NormalType},
      {"action", NormalType},
      {"enabled", IntType},
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
  };

  validate_rows(rows, row_map);
}

TEST_F(windows_firewall_rules, test_sanity) {
  auto const data =
      execute_query("select * from windows_firewall_rules LIMIT 1");

  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"name", NormalType},
      {"app_name", NormalType},
      {"action", NormalType},
      {"enabled", IntType},
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
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
