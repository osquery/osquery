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

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genLogicalDrives(QueryContext& context) {
  QueryData results;

  WmiRequest wmiLogicalDiskReq(
      "select DeviceID, DriveType, FreeSpace, Size, FileSystem from "
      "Win32_LogicalDisk");
  std::vector<WmiResultItem>& wmiResults = wmiLogicalDiskReq.results();
  for (unsigned int i = 0; i < wmiResults.size(); ++i) {
    Row r;
    unsigned int driveType = 0;
    std::string deviceId;
    wmiResults[i].GetString("DeviceID", deviceId);
    wmiResults[i].GetUnsignedInt32("DriveType", driveType);
    wmiResults[i].GetString("FreeSpace", r["free_space"]);
    wmiResults[i].GetString("Size", r["size"]);
    wmiResults[i].GetString("FileSystem", r["file_system"]);

    r["device_id"] = deviceId;

    switch (driveType) {
    default:
      r["type"] = TEXT("Unknown");
      break;
    case 1:
      r["type"] = TEXT("No Root Directory");
      break;
    case 2:
      r["type"] = TEXT("Removable Disk");
      break;
    case 3:
      r["type"] = TEXT("Local Disk");
      break;
    case 4:
      r["type"] = TEXT("Network Drive");
      break;
    case 5:
      r["type"] = TEXT("Compact Disc");
      break;
    case 6:
      r["type"] = TEXT("RAM Disk");
      break;
    }

    r["boot_partition"] = INTEGER(0);

    std::string assocQuery =
        std::string("Associators of {Win32_LogicalDisk.DeviceID='") + deviceId +
        "'} where AssocClass=Win32_LogicalDiskToPartition";

    WmiRequest wmiLogicalDiskToPartitionReq(assocQuery);
    std::vector<WmiResultItem>& wmiLogicalDiskToPartitionResults =
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
    WmiRequest wmiPartitionReq(partitionQuery);
    std::vector<WmiResultItem>& wmiPartitionResults = wmiPartitionReq.results();

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
