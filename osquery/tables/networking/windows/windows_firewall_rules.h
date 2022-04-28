/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <vector>

#include <netfw.h>

namespace osquery {
namespace tables {

enum class WindowsFirewallError {
  NetFwPolicyError,
  PolicyRulesError,
  PolicyRulesEnumError,
  PolicyRulesEnumInterfaceError,
  PolicyRulesEnumNextError,
  PolicyRulesEnumIDispatchError,
  PolicyRuleInterfaceError,
  RuleNameError,
  RuleAppNameError,
  RuleActionError,
  RuleEnabledError,
  RuleGroupingError,
  RuleDirectionError,
  RuleProtocolError,
  RuleLocalAddressesError,
  RuleRemoteAddressesError,
  RuleLocalPortsError,
  RuleRemotePortsError,
  RuleICMPTypesCodesError,
  RuleProfilesError,
  RuleServiceNameError,
};

struct WindowsFirewallRule {
  std::string name;
  std::string appName;
  NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
  bool enabled = false;
  std::string grouping;
  NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
  long protocol = 0;
  std::string localAddresses;
  std::string remoteAddresses;
  std::string localPorts;
  std::string remotePorts;
  std::string icmpTypesCodes;
  long profileBitmask = 0;
  std::string serviceName;
};

using WindowsFirewallRules = std::vector<WindowsFirewallRule>;

QueryData renderWindowsFirewallRules(const WindowsFirewallRules& rules);

} // namespace tables
} // namespace osquery