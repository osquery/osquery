/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genLogicalDrives(QueryContext& context) {
  QueryData results;

  const WmiRequest wmiLogicalDiskReq(
      "select DeviceID, Description, FreeSpace, Size, FileSystem from "
      "Win32_LogicalDisk");
  auto const& logicalDisks = wmiLogicalDiskReq.results();
  for (const auto& logicalDisk : logicalDisks) {
    Row r;
    std::string deviceId;
    r["free_space"] = r["size"] = "-1";
    logicalDisk.GetString("DeviceID", deviceId);
    logicalDisk.GetString("Description", r["description"]);
    logicalDisk.GetString("FreeSpace", r["free_space"]);
    logicalDisk.GetString("Size", r["size"]);
    logicalDisk.GetString("FileSystem", r["file_system"]);

    // NOTE(ww): Previous versions of this table used the type
    // column to provide a non-canonical description of the drive.
    // However, a bug in WMI marshalling caused the type to always
    // return "Unknown". That behavior is preserved here.
    r["type"] = "Unknown";
    r["device_id"] = deviceId;
    r["boot_partition"] = INTEGER(0);

    std::string assocQuery =
        std::string("Associators of {Win32_LogicalDisk.DeviceID='") + deviceId +
        "'} where AssocClass=Win32_LogicalDiskToPartition";

    const WmiRequest wmiLogicalDiskToPartitionReq(assocQuery);
    auto const& wmiLogicalDiskToPartitionResults =
        wmiLogicalDiskToPartitionReq.results();

    if (wmiLogicalDiskToPartitionResults.empty()) {
      results.push_back(r);
      continue;
    }
    std::string partitionDeviceId;
    wmiLogicalDiskToPartitionResults[0].GetString("DeviceID",
                                                  partitionDeviceId);

    std::string partitionQuery =
        std::string(
            "SELECT BootPartition FROM Win32_DiskPartition WHERE DeviceID='") +
        partitionDeviceId + '\'';
    const WmiRequest wmiPartitionReq(partitionQuery);
    auto const& wmiPartitionResults = wmiPartitionReq.results();

    if (wmiPartitionResults.empty()) {
      results.push_back(r);
      continue;
    }
    bool bootPartition = false;
    wmiPartitionResults[0].GetBool("BootPartition", bootPartition);
    r["boot_partition"] = bootPartition ? INTEGER(1) : INTEGER(0);
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
