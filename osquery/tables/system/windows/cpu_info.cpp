/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genCpuInfo(QueryContext& context) {
  Row r;
  QueryData results;

  WmiRequest wmiSystemReq("SELECT * FROM Win32_Processor");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (wmiResults.empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }
  for (const auto& data : wmiResults) {
    long number = 0;
    data.GetString("DeviceID", r["device_id"]);
    data.GetString("SocketDesignation", r["socket_designation"]);
    data.GetString("Name", r["model"]);
    data.GetString("Manufacturer", r["manufacturer"]);
    (data.GetLong("ProcessorType", number))
        ? r["processor_type"] = INTEGER(number)
        : r["processor_type"] = "-1";
    (data.GetLong("Availability", number)) ? r["availability"] = INTEGER(number)
                                           : r["availability"] = "-1";
    (data.GetLong("CpuStatus", number)) ? r["cpu_status"] = INTEGER(number)
                                        : r["cpu_status"] = "-1";
    (data.GetLong("NumberOfCores", number))
        ? r["number_of_cores"] = INTEGER(number)
        : r["number_of_cores"] = "-1";
    (data.GetLong("NumberOfLogicalProcessors", number))
        ? r["logical_processors"] = INTEGER(number)
        : r["logical_processors"] = "-1";
    (data.GetLong("AddressWidth", number))
        ? r["address_width"] = INTEGER(number)
        : r["address_width"] = "-1";
    (data.GetLong("CurrentClockSpeed", number))
        ? r["current_clock_speed"] = INTEGER(number)
        : r["current_clock_speed"] = "-1";
    (data.GetLong("MaxClockSpeed", number))
        ? r["max_clock_speed"] = INTEGER(number)
        : r["max_clock_speed"] = "-1";
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
