/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_set>

#include "osquery/core/windows/wmi.h"
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

QueryData genLogicalDrives(QueryContext& context) {
  QueryData results;
  std::unordered_set<char> bootDeviceIds;

  const auto wmiBootConfigurationReq = WmiRequest::CreateWmiRequest(
      "select BootDirectory from Win32_BootConfiguration");
  if (wmiBootConfigurationReq) {
    auto const& bootConfigurations = wmiBootConfigurationReq->results();

    for (const auto& bootConfiguration : bootConfigurations) {
      std::string bootDirectory;
      bootConfiguration.GetString("BootDirectory", bootDirectory);
      bootDeviceIds.insert(bootDirectory.at(0));
    }
  } else {
    LOG(WARNING) << "Failed to query BootConfiguration via WMI";
  }

  const auto wmiLogicalDiskReq = WmiRequest::CreateWmiRequest(
      "select DeviceID, Description, FreeSpace, Size, FileSystem from "
      "Win32_LogicalDisk");
  if (!wmiLogicalDiskReq) {
    // WMI request failed, which would mean an empty vector for logicalDisks
    // so just return the empty results early.
    LOG(WARNING) << "Failed to query LogicalDisk via WMI";
    return results;
  }
  auto const& logicalDisks = wmiLogicalDiskReq->results();
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

    // NOTE(ww): Previous versions of this table used the type
    // column to provide a non-canonical description of the drive.
    // However, a bug in WMI marshalling caused the type to always
    // return "Unknown". That behavior is preserved here.
    r["type"] = "Unknown";
    r["device_id"] = deviceId;
    r["boot_partition"] = INTEGER(bootDeviceIds.count(deviceId.at(0)));

    results.push_back(std::move(r));
  }
  return results;
}
} // namespace tables
} // namespace osquery
