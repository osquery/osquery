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

enum class SystemError {
  COMError = 1,
};

// Implementation
namespace {

Row renderFirewallRule(const FirewallRule& rule) {
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

  r["enabled"] = INTEGER(bool(rule.enabled));

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
      INTEGER(bool(rule.profileBitmask & NET_FW_PROFILE2_DOMAIN));
  r["profile_private"] =
      INTEGER(bool(rule.profileBitmask & NET_FW_PROFILE2_PRIVATE));
  r["profile_public"] =
      INTEGER(bool(rule.profileBitmask & NET_FW_PROFILE2_PUBLIC));

  return r;
}

Expected<FirewallRules, SystemError> createRulesCOMError(
    HRESULT hr, const std::string& msg) {
  return createError(SystemError::COMError)
         << msg << ", HRESULT=0x" << std::hex << hr;
}

Expected<FirewallRule, SystemError> createRuleCOMError(HRESULT hr,
                                                       const std::string& msg) {
  return createError(SystemError::COMError)
         << msg << ", HRESULT=0x" << std::hex << hr;
}

typedef HRESULT (STDMETHODCALLTYPE INetFwRule::*BSTRFunc)(BSTR*);
HRESULT getString(INetFwRule* rule, BSTRFunc fn, std::string* s) {
  HRESULT hr = S_OK;

  CComBSTR bstr;
  if (FAILED(hr = (rule->*fn)(&bstr))) {
    return hr;
  }
  *s = bstrToString(bstr);
  return hr;
}

Expected<FirewallRule, SystemError> populateFirewallRule(INetFwRule* rule) {
  FirewallRule r;
  HRESULT hr = S_OK;

  if (FAILED(hr = getString(rule, &INetFwRule::get_Name, &r.name))) {
    return createRuleCOMError(hr, "Failed to get firewall rule name");
  }

  if (FAILED(
          hr = getString(rule, &INetFwRule::get_ApplicationName, &r.appName))) {
    return createRuleCOMError(hr,
                              "Failed to get firewall rule application name");
  }

  if (FAILED(hr = rule->get_Action(&r.action))) {
    return createRuleCOMError(hr, "Failed to get firewall rule action");
  }

  VARIANT_BOOL enabled;
  if (FAILED(hr = rule->get_Enabled(&enabled))) {
    return createRuleCOMError(hr, "Failed to get firewall rule enabled");
  }
  r.enabled = enabled;

  if (FAILED(hr = rule->get_Direction(&r.direction))) {
    return createRuleCOMError(hr, "Failed to get firewall rule direction");
  }

  if (FAILED(hr = rule->get_Protocol(&r.protocol))) {
    return createRuleCOMError(hr, "Failed to get firewall rule protocol");
  }

  if (FAILED(hr = getString(
                 rule, &INetFwRule::get_LocalAddresses, &r.localAddresses))) {
    return createRuleCOMError(hr,
                              "Failed to get firewall rule local addresses");
  }

  if (FAILED(hr = getString(
                 rule, &INetFwRule::get_RemoteAddresses, &r.remoteAddresses))) {
    return createRuleCOMError(hr,
                              "Failed to get firewall rule remote addresses");
  }

  if (r.protocol != NET_FW_IP_VERSION_V4 &&
      r.protocol != NET_FW_IP_VERSION_V6) {
    if (FAILED(
            hr = getString(rule, &INetFwRule::get_LocalPorts, &r.localPorts))) {
      return createRuleCOMError(hr, "Failed to get firewall rule local ports");
    }

    if (FAILED(hr = getString(
                   rule, &INetFwRule::get_RemotePorts, &r.remotePorts))) {
      return createRuleCOMError(hr, "Failed to get firewall rule remote ports");
    }

  } else {
    if (FAILED(hr = getString(rule,
                              &INetFwRule::get_IcmpTypesAndCodes,
                              &r.icmpTypesCodes))) {
      return createRuleCOMError(
          hr, "Failed to get firewall rule ICMP types and codes");
    }
  }

  if (FAILED(hr = rule->get_Profiles(&r.profileBitmask))) {
    return createRuleCOMError(hr, "Failed to get firewall rule profiles");
  }

  return r;
}

Expected<FirewallRules, SystemError> getFirewallRules(QueryContext& context) {
  FirewallRules results;

  CComPtr<INetFwPolicy2> netFwPolicy;
  HRESULT hr = netFwPolicy.CoCreateInstance(CLSID_NetFwPolicy2);
  if (FAILED(hr)) {
    return createRulesCOMError(hr, "Failed to instantiate INetFwPolicy2");
  }

  CComPtr<INetFwRules> rules;
  hr = netFwPolicy->get_Rules(&rules);
  if (FAILED(hr)) {
    return createRulesCOMError(hr, "Failed to get firewall rules from policy");
  }

  CComPtr<IUnknown> enumerator;
  hr = rules->get__NewEnum(&enumerator);
  if (FAILED(hr)) {
    return createRulesCOMError(hr, "Failed to get firewall rules enumerator");
  }

  CComPtr<IEnumVARIANT> enumvar;
  hr = enumerator->QueryInterface(IID_PPV_ARGS(&enumvar));
  if (FAILED(hr)) {
    return createRulesCOMError(
        hr, "Failed to get firewall rules enumerator interface");
  }

  do {
    CComVariant value;
    ULONG fetched = 0;
    hr = enumvar->Next(1, &value, &fetched);
    if (FAILED(hr)) {
      return createRulesCOMError(hr, "Failed to enumerate next firewall rule");
    }

    if (hr != S_FALSE) {
      hr = value.ChangeType(VT_DISPATCH);
      if (FAILED(hr)) {
        return createRulesCOMError(
            hr, "Failed to get IDispatch for enumerated rule");
      }

      CComPtr<INetFwRule> rule;
      hr = (V_DISPATCH(&value))->QueryInterface(IID_PPV_ARGS(&rule));
      if (FAILED(hr)) {
        return createRulesCOMError(hr, "Failed to get firewall rule interface");
      }

      auto r = populateFirewallRule(rule);
      if (r.isError()) {
        return r.takeError();
      }

      results.push_back(std::move(r.get()));
    }
  } while (SUCCEEDED(hr) && hr != S_FALSE);

  return results;
}

} // namespace

QueryData renderFirewallRules(const FirewallRules& rules) {
  QueryData results;
  std::for_each(rules.cbegin(), rules.cend(), [&](const FirewallRule& rule) {
    results.push_back(renderFirewallRule(rule));
  });
  return results;
}

QueryData genFirewallRules(QueryContext& context) {
  auto rules = getFirewallRules(context);
  if (rules.isError()) {
    TLOG << "Failed to get firewall rules: " << rules.getError().getMessage();
    return QueryData();
  }
  return renderFirewallRules(rules.get());
}

} // namespace tables
} // namespace osquery
