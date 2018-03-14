/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genDiskInfo(QueryContext& context) {
  Row r;
  QueryData results;

  WmiRequest wmiSystemReq("select * from Win32_DiskDrive");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (!wmiResults.empty()) {
    for (const auto& data : wmiResults) {
      long partitionCount = 0;
      long index = 0;
      data.GetLong("Partitions", partitionCount);
      r["partitions"] = INTEGER(partitionCount);
      data.GetLong("Index", index);
      r["disk_index"] = INTEGER(index);
      data.GetString("InterfaceType", r["type"]);
      data.GetString("PNPDeviceID", r["pnp_device_id"]);
      data.GetString("DeviceID", r["id"]);
      data.GetString("Size", r["disk_size"]);
      data.GetString("Manufacturer", r["manufacturer"]);
      data.GetString("Model", r["hardware_model"]);
      data.GetString("Name", r["name"]);
      data.GetString("SerialNumber", r["serial"]);
      data.GetString("Description", r["description"]);
      results.push_back(r);
    }
  } else {
    r["partitions"] = "-1";
    r["disk_index"] = "-1";
    r["type"] = "-1";
    r["pnp_device_id"] = "-1";
    r["id"] = "-1";
    r["disk_size"] = "-1";
    r["manufacturer"] = "-1";
    r["hardware_model"] = "-1";
    r["name"] = "-1";
    r["serial"] = "-1";
    r["description"] = "-1";
  }

  return results;
}
} // namespace tables
} // namespace osquery