/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sstream>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genPerfProcProcess(QueryContext& context) {
  QueryData results_data;
  const WmiRequest request(
    "SELECT CreatingProcessID, ElapsedTime, HandleCount, Name, "
    "PageFileBytes, PageFileBytesPeak, PercentPrivilegedTime, "
    "PercentProcessorTime, PercentUserTime FROM "
    "Win32_PerfFormattedData_PerfProc_Process");

  if (request.getStatus().ok()) {
    const auto& results = request.results();
    for (const auto& result : results) {
      Row r;
      long process_id = 0;
      long handle_count = 0;
      result.GetLong("CreatingProcessID", process_id);
      r["pid"] = INTEGER(process_id);
      result.GetString("ElapsedTime", r["elapsed_time"]);
      result.GetLong("HandleCount", handle_count);
      r["handle_count"] = INTEGER(handle_count);
      result.GetString("Name", r["name"]);
      result.GetString("PageFileBytes", r["page_file_bytes"]);
      result.GetString("PageFileBytesPeak", r["page_file_bytes_peak"]);
      result.GetString("PercentPrivilegedTime", r["percent_privileged_time"]);
      result.GetString("PercentProcessorTime", r["percent_processor_time"]);
      result.GetString("PercentUserTime", r["percent_user_time"]);
      results_data.push_back(r);
    }
  }

  return results_data;
}
} // namespace tables
} // namespace osquery
