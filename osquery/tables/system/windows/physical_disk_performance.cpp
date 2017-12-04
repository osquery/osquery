/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
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
    unsigned long long ullPlaceHolder = 0;

    disk.GetString("Name", r["name"]);

    disk.GetString("AvgDiskBytesPerRead", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["avg_disk_bytes_per_read"] = BIGINT(ullPlaceHolder);
    disk.GetString("AvgDiskBytesPerWrite", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["avg_disk_bytes_per_write"] = BIGINT(ullPlaceHolder);

    disk.GetString("AvgDiskReadQueueLength", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["avg_disk_read_queue_length"] = BIGINT(ullPlaceHolder);
    disk.GetString("AvgDiskWriteQueueLength", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["avg_disk_write_queue_length"] = BIGINT(ullPlaceHolder);

    disk.GetString("AvgDiskSecPerRead", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["avg_disk_sec_per_read"] = INTEGER(ullPlaceHolder);
    disk.GetString("AvgDiskSecPerWrite", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["avg_disk_sec_per_write"] = INTEGER(ullPlaceHolder);

    disk.GetString("PercentDiskReadTime", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["percent_disk_read_time"] = INTEGER(ullPlaceHolder);
    disk.GetString("PercentDiskWriteTime", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["percent_disk_write_time"] = INTEGER(ullPlaceHolder);

    disk.GetString("CurrentDiskQueueLength", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["current_disk_queue_length"] = INTEGER(ullPlaceHolder);

    disk.GetString("PercentDiskTime", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["percent_disk_time"] = INTEGER(ullPlaceHolder);

    disk.GetString("PercentIdleTime", sPlaceHolder);
    safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
    r["percent_idle_time"] = INTEGER(ullPlaceHolder);

    results.push_back(r);
  }
  return results;
}
}
}
