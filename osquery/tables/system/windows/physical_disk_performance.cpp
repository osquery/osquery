/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genPhysicalDiskPerformance(QueryContext& context) {
  QueryData results;

  auto query = "SELECT * FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk";
  WmiRequest perfReq(query);
  if (!perfReq.getStatus().ok()) {
    return results;
  }
  auto& perfRes = perfReq.results();
  for (const auto& disk : perfRes) {
    Row r;
    std::string sPlaceHolder;

    disk.GetString("Name", r["name"]);

    disk.GetString("AvgDiskBytesPerRead", sPlaceHolder);
    r["avg_disk_bytes_per_read"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).take_or(0));
    disk.GetString("AvgDiskBytesPerWrite", sPlaceHolder);
    r["avg_disk_bytes_per_write"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    disk.GetString("AvgDiskReadQueueLength", sPlaceHolder);
    r["avg_disk_read_queue_length"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).take_or(0));
    disk.GetString("AvgDiskWriteQueueLength", sPlaceHolder);
    r["avg_disk_write_queue_length"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    disk.GetString("AvgDiskSecPerRead", sPlaceHolder);
    r["avg_disk_sec_per_read"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));
    disk.GetString("AvgDiskSecPerWrite", sPlaceHolder);
    r["avg_disk_sec_per_write"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    disk.GetString("PercentDiskReadTime", sPlaceHolder);
    r["percent_disk_read_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));
    disk.GetString("PercentDiskWriteTime", sPlaceHolder);
    r["percent_disk_write_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    disk.GetString("CurrentDiskQueueLength", sPlaceHolder);
    r["current_disk_queue_length"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    disk.GetString("PercentDiskTime", sPlaceHolder);
    r["percent_disk_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    disk.GetString("PercentIdleTime", sPlaceHolder);
    r["percent_idle_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).take_or(0));

    results.push_back(r);
  }
  return results;
}
}
}
