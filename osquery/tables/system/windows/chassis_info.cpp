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

  WmiRequest wmiSystemReq("select * from Win32_SystemEnclosure");
  const auto& wmiResults = wmiSystemReq.results();

  // check if the results are empty and return a warning if so
  if (wmiResults.empty()) {
    LOG(WARNING) << wmiSystemReq.getStatus().getMessage();
    return results;
  }

  for (const auto& data : wmiResults) {
    Row r;
    bool boolean = false;
    long number;
    data.GetBool("AudibleAlarm", boolean);
    r["audible_alarm"] = boolean ? "True" : "False";
    data.GetString("BreachDescription", r["breach_description"]);
    data.GetLong("ChassisTypes", number);
    r["chassis_types"] = INTEGER(number);
    data.GetString("Description", r["description"]);

    // reset boolean to make sure there is no interference from the last call
    boolean = false;

    data.GetBool("LockPresent", boolean);
    r["lock"] = boolean ? "True" : "False";
    data.GetString("Manufacturer", r["manufacturer"]);
    data.GetString("Model", r["model"]);
    data.GetLong("SecurityBreach", number);
    r["security_status"] = INTEGER(number);
    data.GetString("SerialNumber", r["serial"]);
    data.GetString("SMBIOSAssetTag", r["smbios_tag"]);
    data.GetString("SKU", r["sku"]);
    data.GetString("Status", r["status"]);

    // reset boolean to make sure there is no interference from the last call
    boolean = false;

    data.GetBool("VisibleAlarm", boolean);
    r["visible_alarm"] = boolean ? "True" : "False";
    results.push_back(std::move(r));
    return results;
  }

}

  
} // namespace tables
} // namespace osquery
