#include "osquery/core/windows/wmi.h"
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genLogicalDrives(QueryContext& context) {
  Row r;
  QueryData results;

  WmiRequest wmiLogicalDiskReq(
      "select DeviceID, DriveType, FreeSpace, Size, FileSystem from "
      "Win32_LogicalDisk");
  std::vector<WmiResultItem>& wmiResults = wmiLogicalDiskReq.results();
  for (unsigned int i = 0; i < wmiResults.size(); ++i) {
    unsigned int driveType = 0;
    std::string deviceId;
    wmiResults[i].GetString("DeviceID", deviceId);
    r["device_id"] = deviceId;
    wmiResults[i].GetUnsignedInt32("DriveType", driveType);
    wmiResults[i].GetString("FreeSpace", r["free_space"]);
    wmiResults[i].GetString("Size", r["size"]);
    wmiResults[i].GetString("FileSystem", r["file_system"]);

    switch (driveType) {
    case 0:
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

    std::stringstream assoc_query_ss;
    assoc_query_ss << "Associators of {Win32_LogicalDisk.DeviceID='" << deviceId
                   << "'} where AssocClass=Win32_LogicalDiskToPartition";

    WmiRequest wmiLogicalDiskToPartitionReq(assoc_query_ss.str());
    std::vector<WmiResultItem>& wmiLogicalDiskToPartitionResults =
        wmiLogicalDiskToPartitionReq.results();
    std::string partition_device_id;
    r["boot_partition"] = INTEGER(0);
    for (unsigned int i = 0; i < wmiLogicalDiskToPartitionResults.size(); ++i) {
      wmiLogicalDiskToPartitionResults[i].GetString("DeviceID",
                                                    partition_device_id);
      std::stringstream partition_query_ss;
      partition_query_ss
          << "SELECT BootPartition FROM Win32_DiskPartition WHERE DeviceID='"
          << partition_device_id << "'";
      WmiRequest wmiPartitionReq(partition_query_ss.str());
      std::vector<WmiResultItem>& wmiPartitionResults =
          wmiPartitionReq.results();
      bool bootPartition = false;
      if (wmiPartitionResults.size()) {
        wmiPartitionResults[0].GetBool("BootPartition", bootPartition);
      }
      r["boot_partition"] = bootPartition ? INTEGER(1) : INTEGER(0);
    }
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
