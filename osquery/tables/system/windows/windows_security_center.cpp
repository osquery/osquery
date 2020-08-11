/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <windows.h>
#include <wscapi.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/map_take.h>

namespace osquery {
namespace tables {

const auto kSecurityProviderStates = std::unordered_map<int, std::string>{
    {WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED, "Not Monitored"},
    {WSC_SECURITY_PROVIDER_HEALTH_GOOD, "Good"},
    {WSC_SECURITY_PROVIDER_HEALTH_POOR, "Poor"},
    {WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, "Snoozed"},
};

std::string resolveProductHealthOrError(int productName) {
  // Attempt a runtime link to the DLL containing these functions,
  // since linking the library was causing a crash on some Windows
  // machines (like the CI server).
  typedef HRESULT(WINAPI * pWscGetSecurityProviderHealth)(
      _In_ DWORD Providers, _Out_ PWSC_SECURITY_PROVIDER_HEALTH);
  pWscGetSecurityProviderHealth WscGetSecurityProviderHealth;
  static HMODULE hDLL =
      LoadLibraryExW(L"wscapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (hDLL == nullptr) {
    VLOG(1) << "Could not dynamically load 'wscapi.dll'";
    return "Error";
  }

  HRESULT result = E_UNEXPECTED;
  WSC_SECURITY_PROVIDER_HEALTH health;
  WscGetSecurityProviderHealth = (pWscGetSecurityProviderHealth)GetProcAddress(
      hDLL, "WscGetSecurityProviderHealth");
  if (WscGetSecurityProviderHealth == nullptr) {
    VLOG(1) << "Could not load function WscGetSecurityProviderHealth";
    return "Error";
  }

  result = WscGetSecurityProviderHealth(productName, &health);
  if (result != S_OK) {
    VLOG(1) << "Error returned from function WscGetSecurityProviderHealth";
    return "Error";
  }

  return tryTakeCopy(kSecurityProviderStates, health)
      .takeOr(std::string("Unknown"));
}

bool windowsUpdateServicesEnabled() {
  auto wuauservResult =
      SQL::selectAllFrom("services", "name", EQUALS, "wuauserv");
  auto usosvcResult = SQL::selectAllFrom("services", "name", EQUALS, "UsoSvc");

  if (wuauservResult.empty() || usosvcResult.empty()) {
    return false;
  }

  auto& wuauservRow = wuauservResult.at(0);
  auto& usosvcRow = usosvcResult.at(0);

  // If the column changed or doesn't exist, we should just fall through and
  // and let the API report accurately.
  if (wuauservRow.count("start_type") == 0 ||
      usosvcRow.count("start_type") == 0) {
    VLOG(1)
        << "The 'services' virtual table results are missing key 'start_type'";
    return true;
  }

  if (wuauservRow.at("start_type") == "DISABLED" ||
      usosvcRow.at("start_type") == "DISABLED") {
    return false;
  }

  return true;
}

// In our testing, the autoupdate health check shows "Good", even if essential
// services are disabled. If the the standard API call is "Good". we verify
// these services are NOT disabled before we let the table return the "Good"
// result
std::string genWindowsUpdateHealth() {
  std::string productHealth =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS);
  if (productHealth == "Good" && !windowsUpdateServicesEnabled()) {
    return "Poor";
  }

  return productHealth;
}

QueryData gen_wsc(QueryContext& context) {
  QueryData results;
  Row r;

  r["firewall"] = resolveProductHealthOrError(WSC_SECURITY_PROVIDER_FIREWALL);
  r["antivirus"] = resolveProductHealthOrError(WSC_SECURITY_PROVIDER_ANTIVIRUS);
  r["autoupdate"] = genWindowsUpdateHealth();
  r["antispyware"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_ANTISPYWARE);
  r["internet_settings"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_INTERNET_SETTINGS);
  r["user_account_control"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL);
  r["windows_security_center_service"] =
      resolveProductHealthOrError(WSC_SECURITY_PROVIDER_SERVICE);

  results.push_back(r);
  return results;
}

} // namespace tables
} // namespace osquery
