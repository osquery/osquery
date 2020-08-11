/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

QueryData genSystemInfo(QueryContext& context) {
  Row r;
  r["hostname"] = osquery::getFqdn();
  r["computer_name"] = osquery::getHostname();
  r["local_hostname"] = r["computer_name"];
  getHostUUID(r["uuid"]);

  auto qd = SQL::selectAllFrom("cpuid");
  for (const auto& row : qd) {
    if (row.at("feature") == "product_name") {
      r["cpu_brand"] = row.at("value");
      boost::trim(r["cpu_brand"]);
    }
  }

  const WmiRequest wmiSystemReq("select * from Win32_ComputerSystem");
  const WmiRequest wmiSystemReqProc("select * from Win32_Processor");
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  const std::vector<WmiResultItem>& wmiResultsProc = wmiSystemReqProc.results();
  if (!wmiResults.empty() && !wmiResultsProc.empty()) {
    long numProcs = 0;
    wmiResults[0].GetLong("NumberOfLogicalProcessors", numProcs);
    r["cpu_logical_cores"] = INTEGER(numProcs);
    wmiResultsProc[0].GetLong("NumberOfCores", numProcs);
    r["cpu_physical_cores"] = INTEGER(numProcs);
    wmiResults[0].GetString("TotalPhysicalMemory", r["physical_memory"]);
    wmiResults[0].GetString("Manufacturer", r["hardware_vendor"]);
    wmiResults[0].GetString("Model", r["hardware_model"]);
  } else {
    r["cpu_logical_cores"] = "-1";
    r["cpu_physical_cores"] = "-1";
    r["physical_memory"] = "-1";
    r["hardware_vendor"] = "-1";
    r["hardware_model"] = "-1";
  }

  QueryData regResults;
  queryKey(
      "HKEY_LOCAL_MACHINE\\"
      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\",
      regResults);
  for (const auto& key : regResults) {
    if (key.at("name") == "Update Revision") {
      if (key.at("data").size() >= 16) {
        auto revision_exp =
            tryTo<unsigned long int>(key.at("data").substr(8, 2), 16);
        r["cpu_microcode"] = std::to_string(revision_exp.takeOr(0ul));
      }
      break;
    }
  }

  const WmiRequest wmiBiosReq("select * from Win32_Bios");
  const std::vector<WmiResultItem>& wmiBiosResults = wmiBiosReq.results();
  if (wmiBiosResults.size() != 0) {
    wmiBiosResults[0].GetString("SerialNumber", r["hardware_serial"]);
  } else {
    r["hardware_serial"] = "-1";
  }

  SYSTEM_INFO systemInfo;
  GetSystemInfo(&systemInfo);
  switch (systemInfo.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    r["cpu_type"] = "x86_64";
    break;
  case PROCESSOR_ARCHITECTURE_ARM:
    r["cpu_type"] = "ARM";
    break;
  case PROCESSOR_ARCHITECTURE_IA64:
    r["cpu_type"] = "x64 Itanium";
    break;
  case PROCESSOR_ARCHITECTURE_INTEL:
    r["cpu_type"] = "x86";
    break;
  case PROCESSOR_ARCHITECTURE_UNKNOWN:
    r["cpu_type"] = "Unknown";
  default:
    break;
  }

  r["cpu_subtype"] = "-1";
  r["hardware_version"] = "-1";
  return {r};
}
}
}
