/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

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
    std::vector<long> chassisTypes;
    data.GetBool("AudibleAlarm", isPresent);
    r["audible_alarm"] = isPresent ? "True" : "False";
    data.GetString("BreachDescription", r["breach_description"]);
    data.GetVectorOfLongs("ChassisTypes", chassisTypes);

    std::ostringstream oValueConcat;
    for (size_t i = 0; i < chassisTypes.size(); ++i) {
      if (i != 0) {
        oValueConcat << ",";
      }
      oValueConcat << chassisTypes[i];
    }

    r["chassis_types"] = SQL_TEXT(oValueConcat.str());
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
