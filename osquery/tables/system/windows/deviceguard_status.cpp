/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

QueryData genDeviceGuardStatus(QueryContext& context) {
  QueryData results;

  std::vector<std::string> vbs_methods = {"VBS_NOT_ENABLED",
                                          "VBS_ENABLED_AND_NOT_RUNNING",
                                          "VBS_ENABLED_AND_RUNNING"};

  std::vector<std::string> security_services = {"NONE",
                                                "CREDENTIAL_GUARD",
                                                "MEMORY_INTEGRITY",
                                                "SYSTEM_GUARD_SECURE_LAUNCH",
                                                "SMM_FIRMWARE_MEASUREMENT"};

  std::vector<std::string> enforcement_methods = {
      "OFF", "AUDIT_MODE", "ENFORCED_MODE"};

  const auto wmiSystemReq = WmiRequest::CreateWmiRequest(
      "SELECT * FROM Win32_DeviceGuard",
      (BSTR)L"ROOT\\MICROSOFT\\WINDOWS\\DEVICEGUARD");
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(ERROR) << "Error retreiving information from WMI.";
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();
  for (const auto& data : wmiResults) {
    Row r;
    data.GetString("Version", r["version"]);
    data.GetString("InstanceIdentifier", r["instance_identifier"]);

    long vbs_status;
    data.GetLong("VirtualizationBasedSecurityStatus", vbs_status);
    r["vbs_status"] =
        vbs_methods.size() > vbs_status ? vbs_methods[vbs_status] : "UNKNOWN";

    long code_policy_status;
    data.GetLong("CodeIntegrityPolicyEnforcementStatus", code_policy_status);
    r["code_integrity_policy_enforcement_status"] =
        enforcement_methods.size() > code_policy_status
            ? enforcement_methods[code_policy_status]
            : "UNKNOWN";

    long umci_status;
    data.GetLong("UsermodeCodeIntegrityPolicyEnforcementStatus", umci_status);
    r["umci_policy_status"] = enforcement_methods.size() > umci_status
                                  ? enforcement_methods[umci_status]
                                  : "UNKNOWN";

    std::vector<long> running_security_services;
    data.GetVectorOfLongs("SecurityServicesRunning", running_security_services);
    for (int i = 0; i < running_security_services.size(); i++) {
      r["running_security_services"].append(
          security_services.size() > running_security_services[i]
              ? security_services[running_security_services[i]]
              : "UNKNOWN");
      if (i < (running_security_services.size() - 1)) {
        r["running_security_services"].append(",");
      }
    }

    std::vector<long> configured_security_services;
    data.GetVectorOfLongs("SecurityServicesConfigured",
                          configured_security_services);
    for (int i = 0; i < configured_security_services.size(); i++) {
      r["configured_security_services"].append(
          security_services.size() > configured_security_services[i]
              ? security_services[configured_security_services[i]]
              : "UNKNOWN");
      if (i < (configured_security_services.size() - 1)) {
        r["configured_security_services"].append(",");
      }
    }

    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
