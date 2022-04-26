/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/tables/networking/windows/windows_firewall_rules.h>

namespace osquery {

namespace table_tests {

class WindowsFirewallRulesTests : public testing::Test {};

namespace {
tables::WindowsFirewallRules generateTestRules() {
  tables::WindowsFirewallRules rules;
  tables::WindowsFirewallRule r = {
      "TestName",
      "TestAppName",
      NET_FW_ACTION_BLOCK,
      false,
      "Grouping",
      NET_FW_RULE_DIR_IN,
      NET_FW_IP_VERSION_V4,
      "",
      "",
      "",
      "",
      "",
      0,
      "ServiceName",
  };

  tables::WindowsFirewallRule rule;
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

void validateRendered(const tables::WindowsFirewallRule& rule, Row& row) {
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
  ASSERT_EQ(rule.grouping, row["grouping"]);

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
  ASSERT_EQ(rule.serviceName, row["service_name"]);
}

} // namespace

TEST_F(WindowsFirewallRulesTests, test_firewall_rules_render) {
  auto rules = generateTestRules();
  auto rows = renderWindowsFirewallRules(rules);

  ASSERT_EQ(rows.size(), rules.size());

  size_t i = 0;
  std::for_each(rules.cbegin(),
                rules.cend(),
                [&](const tables::WindowsFirewallRule& rule) {
                  auto row = rows[i++];
                  validateRendered(rule, row);
                });
}

} // namespace table_tests
} // namespace osquery
