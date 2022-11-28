/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>

#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genPhysicalDiskPerformance(QueryContext& context) {
  QueryData results;

  auto query = "SELECT * FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk";
  const auto perfReq = WmiRequest::CreateWmiRequest(query);
  if (!perfReq || !perfReq->getStatus().ok()) {
    return results;
  }
  const auto& perfRes = perfReq->results();
  for (const auto& disk : perfRes) {
    Row r;
    std::string sPlaceHolder;

    disk.GetString("Name", r["name"]);

    disk.GetString("AvgDiskBytesPerRead", sPlaceHolder);
    r["avg_disk_bytes_per_read"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
    disk.GetString("AvgDiskBytesPerWrite", sPlaceHolder);
    r["avg_disk_bytes_per_write"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    disk.GetString("AvgDiskReadQueueLength", sPlaceHolder);
    r["avg_disk_read_queue_length"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
    disk.GetString("AvgDiskWriteQueueLength", sPlaceHolder);
    r["avg_disk_write_queue_length"] =
        BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    disk.GetString("AvgDiskSecPerRead", sPlaceHolder);
    r["avg_disk_sec_per_read"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
    disk.GetString("AvgDiskSecPerWrite", sPlaceHolder);
    r["avg_disk_sec_per_write"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    disk.GetString("PercentDiskReadTime", sPlaceHolder);
    r["percent_disk_read_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
    disk.GetString("PercentDiskWriteTime", sPlaceHolder);
    r["percent_disk_write_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    disk.GetString("CurrentDiskQueueLength", sPlaceHolder);
    r["current_disk_queue_length"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    disk.GetString("PercentDiskTime", sPlaceHolder);
    r["percent_disk_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    disk.GetString("PercentIdleTime", sPlaceHolder);
    r["percent_idle_time"] =
        INTEGER(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

    results.push_back(r);
  }
  return results;
}
}
}
