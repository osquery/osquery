/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <windows.h>
#include <wscapi.h>

#include <osquery/core.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/map_take.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {
namespace tables {

const auto kSecurityProviderStates = std::unordered_map<int, std::string>{
    {WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED, "Not Monitored"},
    {WSC_SECURITY_PROVIDER_HEALTH_GOOD, "Good"},
    {WSC_SECURITY_PROVIDER_HEALTH_POOR, "Poor"},
    {WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, "Snoozed"},
};

std::string resolveProductHealthOrError(int productName) {
  HRESULT result;
  WSC_SECURITY_PROVIDER_HEALTH health;

  result = WscGetSecurityProviderHealth(productName, &health);

  if (result == S_OK) {
    return tryTakeCopy(kSecurityProviderStates, health)
        .takeOr(std::string("Unknown"));
  }

  return "Error";
}

QueryData gen_wsc(QueryContext& context) {
  QueryData results;
  Row r;

  r["global_state"] = resolveProductHealthOrError(WSC_SECURITY_PROVIDER_ALL);
  r["firewall"] = resolveProductHealthOrError(WSC_SECURITY_PROVIDER_FIREWALL);
  r["antivirus"] = resolveProductHealthOrError(WSC_SECURITY_PROVIDER_ANTIVIRUS);
  r["autoupdate"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS);
  r["antispyware"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_ANTISPYWARE);
  r["internet_settings"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_INTERNET_SETTINGS);
  r["user_account_control"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL);
  r["windows_security_center_service"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL);

  results.push_back(r);
  return results;
}

} // namespace tables
} // namespace osquery
