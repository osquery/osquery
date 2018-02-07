/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>

#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"

#define DECLARE_TABLE_IMPLEMENTATION_system_info
#include <generated/tables/tbl_system_info_defs.hpp>

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

  WmiRequest wmiSystemReq("select * from Win32_ComputerSystem");
  WmiRequest wmiSystemReqProc("select * from Win32_Processor");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  std::vector<WmiResultItem>& wmiResultsProc = wmiSystemReqProc.results();
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
        unsigned long int revision = 0;
        safeStrtoul(key.at("data").substr(8, 2), 16, revision);
        r["cpu_microcode"] = std::to_string(revision);
      }
      break;
    }
  }

  WmiRequest wmiBiosReq("select * from Win32_Bios");
  std::vector<WmiResultItem>& wmiBiosResults = wmiBiosReq.results();
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
