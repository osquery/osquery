/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
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
  const std::vector<WmiResultItem>& logicalDisks = wmiLogicalDiskReq.results();
  const WmiRequest wmiBootConfigurationReq(
      "select BootDirectory from Win32_BootConfiguration");
  const std::vector<WmiResultItem>& bootConfigurations =
      wmiBootConfigurationReq.results();

  for (const auto& logicalDisk : logicalDisks) {
    Row r;
    std::string driveType;
    std::string deviceId;
    logicalDisk.GetString("Description", driveType);
    logicalDisk.GetString("DeviceID", deviceId);
    logicalDisk.GetString("FreeSpace", r["free_space"]);
    logicalDisk.GetString("Size", r["size"]);
    logicalDisk.GetString("FileSystem", r["file_system"]);

    r["type"] = driveType;
    r["device_id"] = deviceId;

    int bootPartition = 0;

    for (const auto& bootConfiguration : bootConfigurations) {
      std::string bootDirectory;
      bootConfiguration.GetString("BootDirectory", bootDirectory);

      if (bootDirectory.find(deviceId) == 0) {
        bootPartition = 1;
        break;
      }
    }

    r["boot_partition"] = INTEGER(bootPartition);
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
