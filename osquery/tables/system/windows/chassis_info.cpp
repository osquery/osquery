/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genChassisInfo(QueryContext& context) {
  QueryData results;

  WmiRequest wmiSystemReq("SELECT * FROM Win32_SystemEnclosure");
  const auto& wmiResults = wmiSystemReq.results();

  // check if the results are empty and return a warning if so
  if (wmiResults.empty()) {
    LOG(WARNING) << "Error retrieving information from WMI.";
    return results;
  }

  for (const auto& data : wmiResults) {
    Row r;
    auto isPresent = false;
    long number;
    data.GetBool("AudibleAlarm", isPresent);
    r["audible_alarm"] = isPresent ? "True" : "False";
    data.GetString("BreachDescription", r["breach_description"]);
    data.GetLong("ChassisTypes", number);
    r["chassis_types"] = INTEGER(number);
    data.GetString("Description", r["description"]);

    // reset boolean to make sure there is no interference from the last call
    isPresent = false;

    data.GetBool("LockPresent", isPresent);
    r["lock"] = isPresent ? "True" : "False";
    data.GetString("Manufacturer", r["manufacturer"]);
    data.GetString("Model", r["model"]);
    data.GetLong("SecurityBreach", number);
    r["security_status"] = INTEGER(number);
    data.GetString("SerialNumber", r["serial"]);
    data.GetString("SMBIOSAssetTag", r["smbios_tag"]);
    data.GetString("SKU", r["sku"]);
    data.GetString("Status", r["status"]);

    // reset boolean to make sure there is no interference from the last call
    isPresent = false;

    data.GetBool("VisibleAlarm", isPresent);
    r["visible_alarm"] = isPresent ? "True" : "False";
    results.push_back(std::move(r));
  }

  return results;
}

} // namespace tables
} // namespace osquery
