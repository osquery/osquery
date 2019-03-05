/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <Windows.h>
#include <set>

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

  const WmiRequest wmiBootConfigurationReq(
      "select BootDirectory from Win32_BootConfiguration");
  auto const& bootConfigurations = wmiBootConfigurationReq.results();
  std::set<std::string> bootDirectories;

  for (const auto& bootConfiguration : bootConfigurations) {
    std::string bootDirectory;
    bootConfiguration.GetString("BootDirectory", bootDirectory);
    bootDirectories.insert(std::move(bootDirectory));
  }

  for (const auto& logicalDisk : logicalDisks) {
    Row r;
    std::string deviceId;
    logicalDisk.GetString("DeviceID", deviceId);
    logicalDisk.GetString("Description", r["description"]);
    logicalDisk.GetString("FreeSpace", r["free_space"]);
    logicalDisk.GetString("Size", r["size"]);
    logicalDisk.GetString("FileSystem", r["file_system"]);

    if (r["free_space"].empty()) {
      r["free_space"] = "-1";
    }

    if (r["size"].empty()) {
      r["size"] = "-1";
    }

    std::string bootPath = deviceId + "\\Windows";
    int bootPartition = bootDirectories.count(bootPath);

    // NOTE(ww): Previous versions of this table used the type
    // column to provide a non-canonical description of the drive.
    // However, a bug in WMI marshalling caused the type to always
    // return "Unknown". That behavior is preserved here.
    r["type"] = "Unknown";
    r["device_id"] = deviceId;
    r["boot_partition"] = INTEGER(bootPartition);

    results.push_back(std::move(r));
  }
  return results;
}
} // namespace tables
} // namespace osquery
