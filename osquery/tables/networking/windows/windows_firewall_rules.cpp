/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <atlbase.h>
#include <netfw.h>
#include <windows.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

#include "windows_firewall_rules.h"

namespace osquery {
namespace tables {

// Implementation
namespace {

// Map lookup for error messages per code review request
const std::unordered_map<WindowsFirewallError, std::string>
    kWindowsFirewallErrorDescriptions{
        {WindowsFirewallError::NetFwPolicyError,
         "Failed to instantiate INetFwPolicy2"},
        {WindowsFirewallError::PolicyRulesError,
         "Failed to get firewall rules from policy"},
        {WindowsFirewallError::PolicyRulesEnumError,
         "Failed to get firewall rules enumerator"},
        {WindowsFirewallError::PolicyRulesEnumInterfaceError,
         "Failed to get firewall rules enumerator interface"},
        {WindowsFirewallError::PolicyRulesEnumNextError,
         "Failed to enumerate next firewall rule"},
        {WindowsFirewallError::PolicyRulesEnumIDispatchError,
         "Failed to get IDispatch for enumerated rule"},
        {WindowsFirewallError::PolicyRuleInterfaceError,
         "Failed to get firewall rule interface"},
        {WindowsFirewallError::RuleNameError,
         "Failed to get firewall rule name"},
        {WindowsFirewallError::RuleAppNameError,
         "Failed to get firewall rule application name"},
        {WindowsFirewallError::RuleActionError,
         "Failed to get firewall rule action name"},
        {WindowsFirewallError::RuleEnabledError,
         "Failed to get firewall rule enabled"},
        {WindowsFirewallError::RuleDirectionError,
         "Failed to get firewall rule direction"},
        {WindowsFirewallError::RuleProtocolError,
         "Failed to get firewall rule protocol"},
        {WindowsFirewallError::RuleLocalAddressesError,
         "Failed to get firewall rule local addresses"},
        {WindowsFirewallError::RuleRemoteAddressesError,
         "Failed to get firewall rule remote addresses"},
        {WindowsFirewallError::RuleLocalPortsError,
         "Failed to get firewall rule local ports"},
        {WindowsFirewallError::RuleRemotePortsError,
         "Failed to get firewall rule remote ports"},
        {WindowsFirewallError::RuleICMPTypesCodesError,
         "Failed to get firewall rule ICMP types and codes"},
        {WindowsFirewallError::RuleProfilesError,
         "Failed to get firewall rule profiles"},
    };

std::string getErrorDescription(const WindowsFirewallError& error) {
  auto it = kWindowsFirewallErrorDescriptions.find(error);
  if (it == kWindowsFirewallErrorDescriptions.end()) {
    std::stringstream stream;
    stream << "Unknown error type: 0x" << std::hex
           << static_cast<std::uint64_t>(error);

    return stream.str();
  }

  return it->second;
}

Expected<WindowsFirewallRule, WindowsFirewallError>
createWindowsFirewallRuleError(WindowsFirewallError error, HRESULT hr) {
  return createError(error)
         << getErrorDescription(error) << ", HRESULT=0x" << std::hex << hr;
}

Expected<WindowsFirewallRules, WindowsFirewallError>
createWindowsFirewallRulesError(WindowsFirewallError error, HRESULT hr) {
  return createError(error)
         << getErrorDescription(error) << ", HRESULT=0x" << std::hex << hr;
}

Row renderFirewallRule(const WindowsFirewallRule& rule) {
  Row r;

  r["name"] = rule.name;
  r["app_name"] = rule.appName;

  switch (rule.action) {
  case NET_FW_ACTION_BLOCK:
    r["action"] = "Block";
    break;
  case NET_FW_ACTION_ALLOW:
    r["action"] = "Allow";
    break;
  default:
    r["action"] = "";
    break;
  }

  r["enabled"] = INTEGER(rule.enabled);

  switch (rule.direction) {
  case NET_FW_RULE_DIR_IN:
    r["direction"] = "In";
    break;
  case NET_FW_RULE_DIR_OUT:
    r["direction"] = "Out";
    break;
  default:
    r["direction"] = "";
    break;
  }

  switch (rule.protocol) {
  case NET_FW_IP_PROTOCOL_TCP:
    r["protocol"] = "TCP";
    break;
  case NET_FW_IP_PROTOCOL_UDP:
    r["protocol"] = "UDP";
    break;
  case NET_FW_IP_PROTOCOL_ANY:
    r["protocol"] = "Any";
    break;
  default:
    r["protocol"] = "";
    break;
  }

  r["local_addresses"] = rule.localAddresses;
  r["remote_addresses"] = rule.remoteAddresses;

  if (rule.protocol != NET_FW_IP_VERSION_V4 &&
      rule.protocol != NET_FW_IP_VERSION_V6) {
    r["local_ports"] = rule.localPorts;
    r["remote_ports"] = rule.remotePorts;
    r["icmp_types_codes"] = "";
  } else {
    r["local_ports"] = "";
    r["remote_ports"] = "";
    r["icmp_types_codes"] = rule.icmpTypesCodes;
  }

  r["profile_domain"] =
      INTEGER((rule.profileBitmask & NET_FW_PROFILE2_DOMAIN) != 0);
  r["profile_private"] =
      INTEGER((rule.profileBitmask & NET_FW_PROFILE2_PRIVATE) != 0);
  r["profile_public"] =
      INTEGER((rule.profileBitmask & NET_FW_PROFILE2_PUBLIC) != 0);

  return r;
}

typedef HRESULT (STDMETHODCALLTYPE INetFwRule::*BSTRFunc)(BSTR*);
HRESULT getString(INetFwRule* rule, BSTRFunc fn, std::string& s) {
  HRESULT hr = S_OK;

  CComBSTR bstr;
  if (FAILED(hr = (rule->*fn)(&bstr))) {
    return hr;
  }
  s = bstrToString(bstr);
  return hr;
}

Expected<WindowsFirewallRule, WindowsFirewallError> populateFirewallRule(
    INetFwRule* rule) {
  WindowsFirewallRule r;
  HRESULT hr = S_OK;

  if (FAILED(hr = getString(rule, &INetFwRule::get_Name, r.name))) {
    return createWindowsFirewallRuleError(WindowsFirewallError::RuleNameError,
                                          hr);
  }

  if (FAILED(
          hr = getString(rule, &INetFwRule::get_ApplicationName, r.appName))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleAppNameError, hr);
  }

  if (FAILED(hr = rule->get_Action(&r.action))) {
    return createWindowsFirewallRuleError(WindowsFirewallError::RuleActionError,
                                          hr);
  }

  VARIANT_BOOL enabled;
  if (FAILED(hr = rule->get_Enabled(&enabled))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleEnabledError, hr);
  }
  r.enabled = enabled;

  if (FAILED(hr = rule->get_Direction(&r.direction))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleDirectionError, hr);
  }

  if (FAILED(hr = rule->get_Protocol(&r.protocol))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleProtocolError, hr);
  }

  if (FAILED(hr = getString(
                 rule, &INetFwRule::get_LocalAddresses, r.localAddresses))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleLocalAddressesError, hr);
  }

  if (FAILED(hr = getString(
                 rule, &INetFwRule::get_RemoteAddresses, r.remoteAddresses))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleRemoteAddressesError, hr);
  }

  if (r.protocol != NET_FW_IP_VERSION_V4 &&
      r.protocol != NET_FW_IP_VERSION_V6) {
    if (FAILED(
            hr = getString(rule, &INetFwRule::get_LocalPorts, r.localPorts))) {
      return createWindowsFirewallRuleError(
          WindowsFirewallError::RuleLocalPortsError, hr);
    }

    if (FAILED(hr = getString(
                   rule, &INetFwRule::get_RemotePorts, r.remotePorts))) {
      return createWindowsFirewallRuleError(
          WindowsFirewallError::RuleRemotePortsError, hr);
    }

  } else {
    if (FAILED(hr = getString(rule,
                              &INetFwRule::get_IcmpTypesAndCodes,
                              r.icmpTypesCodes))) {
      return createWindowsFirewallRuleError(
          WindowsFirewallError::RuleICMPTypesCodesError, hr);
    }
  }

  if (FAILED(hr = rule->get_Profiles(&r.profileBitmask))) {
    return createWindowsFirewallRuleError(
        WindowsFirewallError::RuleProfilesError, hr);
  }

  return r;
}

Expected<WindowsFirewallRules, WindowsFirewallError> getFirewallRules(
    QueryContext& context) {
  WindowsFirewallRules results;

  CComPtr<INetFwPolicy2> netFwPolicy;
  HRESULT hr = netFwPolicy.CoCreateInstance(CLSID_NetFwPolicy2);
  if (FAILED(hr)) {
    return createWindowsFirewallRulesError(
        WindowsFirewallError::NetFwPolicyError, hr);
  }

  CComPtr<INetFwRules> rules;
  hr = netFwPolicy->get_Rules(&rules);
  if (FAILED(hr)) {
    return createWindowsFirewallRulesError(
        WindowsFirewallError::PolicyRulesError, hr);
  }

  CComPtr<IUnknown> enumerator;
  hr = rules->get__NewEnum(&enumerator);
  if (FAILED(hr)) {
    return createWindowsFirewallRulesError(
        WindowsFirewallError::PolicyRulesEnumError, hr);
  }

  CComPtr<IEnumVARIANT> enumvar;
  hr = enumerator->QueryInterface(IID_PPV_ARGS(&enumvar));
  if (FAILED(hr)) {
    return createWindowsFirewallRulesError(
        WindowsFirewallError::PolicyRulesEnumInterfaceError, hr);
  }

  for (; (hr != S_FALSE);) {
    CComVariant value;
    ULONG fetched = 0;
    hr = enumvar->Next(1, &value, &fetched);
    if (FAILED(hr)) {
      return createWindowsFirewallRulesError(
          WindowsFirewallError::PolicyRulesEnumNextError, hr);
    }

    if (hr != S_FALSE) {
      hr = value.ChangeType(VT_DISPATCH);
      if (FAILED(hr)) {
        // Log and continue
        auto err = createWindowsFirewallRulesError(
            WindowsFirewallError::PolicyRulesEnumIDispatchError, hr);
        TLOG << err.getError().getMessage();
        hr = S_OK;
        continue;
      }

      CComPtr<INetFwRule> rule;
      hr = (V_DISPATCH(&value))->QueryInterface(IID_PPV_ARGS(&rule));
      if (FAILED(hr)) {
        auto err = createWindowsFirewallRulesError(
            WindowsFirewallError::PolicyRuleInterfaceError, hr);
        TLOG << err.getError().getMessage();
        hr = S_OK;
        continue;
      }

      auto r = populateFirewallRule(rule);
      if (r.isError()) {
        return r.takeError();
      }

      results.push_back(std::move(r.get()));
    }
  }

  return results;
}

} // namespace

QueryData renderWindowsFirewallRules(const WindowsFirewallRules& rules) {
  QueryData results;
  std::for_each(
      rules.cbegin(), rules.cend(), [&](const WindowsFirewallRule& rule) {
        results.push_back(renderFirewallRule(rule));
      });
  return results;
}

QueryData genWindowsFirewallRules(QueryContext& context) {
  auto rules = getFirewallRules(context);
  if (rules.isError()) {
    TLOG << "Failed to get firewall rules: " << rules.getError().getMessage();
    return QueryData();
  }
  return renderWindowsFirewallRules(rules.get());
}

} // namespace tables
} // namespace osquery
