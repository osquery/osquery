#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genHVCIStatus(QueryContext& context) {
  Row r;
  QueryData results;

  const WmiRequest wmiSystemReq("SELECT * FROM Win32_DeviceGuard",
                                (BSTR)L"ROOT\\MICROSOFT\\WINDOWS\\DEVICEGUARD");
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (wmiResults.empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }
  for (const auto& data : wmiResults) {
    long vbsmethod;
    long codepolicystatusmethod;
    long umcipolicymethod;

    data.GetString("Version", r["version"]);
    data.GetString("InstanceIdentifier", r["instance_identifier"]);
    data.GetLong("VirtualizationBasedSecurityStatus", vbsmethod);
    data.GetLong("CodeIntegrityPolicyEnforcementStatus",
                 codepolicystatusmethod);
    data.GetLong("UsermodeCodeIntegrityPolicyEnforcementStatus",
                 umcipolicymethod);
    data.GetVectorOfStrings("AvailableSecurityProperties",
                            r["available_security_properties"]);

    std::string vbsmethod_str;
    std::map<long, std::string> vbsmethods;

    std::string codepolicystatusmethod_str;
    std::map<long, std::string> codepolicystatusmethods;

    std::string umcipolicymethod_str;
    std::map<long, std::string> umcipolicymethods;

    vbsmethods[0] = "VBS_NOT_ENABLED";
    vbsmethods[1] = "VBS_ENABLED_AND_NOT_RUNNING";
    vbsmethods[2] = "VBS_ENABLED_AND_RUNNING";

    codepolicystatusmethods[0] = "OFF";
    codepolicystatusmethods[1] = "AUDIT_MODE";
    codepolicystatusmethods[2] = "ENFORCED_MODE";

    umcipolicymethods[0] = "OFF";
    umcipolicymethods[0] = "AUDIT_MODE";
    umcipolicymethods[0] = "ENFORCED_MODE";

    if (vbsmethods.find(vbsmethod) != vbsmethods.end()) {
      vbsmethod_str = vbsmethods.find(vbsmethod)->second;
    } else {
      vbsmethod_str = "UNKNOWN";
    }

    if (codepolicystatusmethods.find(codepolicystatusmethod) !=
        codepolicystatusmethods.end()) {
      codepolicystatusmethod_str =
          codepolicystatusmethods.find(codepolicystatusmethod)->second;
    } else {
      codepolicystatusmethod_str = "UNKNOWN";
    }

    if (umcipolicymethods.find(umcipolicymethod) != umcipolicymethods.end()) {
      umcipolicymethod_str = umcipolicymethods.find(umcipolicymethod)->second;
    } else {
      umcipolicymethod_str = "UNKNOWN";
    }

    r["vbs_status"] = vbsmethod_str;
    r["code_integirty_policy_enforcement_status"] = codepolicystatusmethod_str;
    r["umci_policy_status"] = umcipolicymethod_str;

    // stuff goes before here
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
// namespace osquery