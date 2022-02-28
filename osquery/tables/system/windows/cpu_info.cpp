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
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genCpuInfo(QueryContext& context) {
  Row r;
  QueryData results;

  const Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_Processor");
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();
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
