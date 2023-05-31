/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/core/windows/wmi.h"
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>

#include <unordered_map>

namespace osquery {
namespace tables {

QueryData genCpuTime(QueryContext& context) {
  QueryData results;

  // System uptime: time since the system was last started, in seconds
  long long uptime; 
  const Expected<WmiRequest, WmiError> wmiSystemReq_uptime =
      WmiRequest::CreateWmiRequest(
          "select SystemUpTime from Win32_PerfFormattedData_PerfOS_System");
  if (!wmiSystemReq_uptime || wmiSystemReq_uptime->results().empty()) {
    LOG(WARNING) << "Error retrieving information from WMI.";
    return results;
  }

  const std::vector<WmiResultItem>& uptimeData = wmiSystemReq_uptime->results();
  uptimeData[0].GetLongLong("SystemUpTime", uptime);

  // Percentage of time each core spent in different parts
  const Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest(
          "select Name, PercentUserTime, PercentPrivilegedTime, "
          "PercentIdleTime, PercentInterruptTime, PercentPriorityTime "
          "from Win32_PerfFormattedData_Counters_ProcessorInformation");
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Error retrieving information from WMI.";
    return results;
  }

  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();
  for (const auto& data : wmiResults) {
    data.GetString("Name", r["core"]);
    long percent = 0;
    data.GetLongLong("PercentUserTime", percent);
    // Hundredths of a second, percent / 100 * uptime * 100
    r["user"] = BIGINT(percent * uptime);
    data.GetLongLong("PercentPrivilegedTime", percent);
    r["system"] = BIGINT(percent * uptime);
    data.GetLongLong("PercentIdleTime", percent);
    r["idle"] = BIGINT(percent * uptime);
    long idle = percent;
    data.GetLongLong("PercentInterruptTime", percent);
    r["irq"] = BIGINT(percent * uptime);
    // Time spent on low priority threads
    data.GetLongLong("PercentPriorityTime", percent);
    r["nice"] = BIGINT((100 - percent - idle) * uptime);
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
