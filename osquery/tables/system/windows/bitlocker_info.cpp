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

QueryData genBitlockerInfo(QueryContext& context) {
  Row r;
  QueryData results;

  WmiRequest wmiSystemReq(
      "SELECT * FROM Win32_EncryptableVolume",
      (BSTR)L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (!wmiResults.empty()) {
    for (const auto& data : wmiResults) {
      long status = 0;
      data.GetString("DeviceID", r["device_id"]);
      data.GetString("DriveLetter", r["drive_letter"]);
      data.GetString("PersistentVolumeID", r["persistent_volume_id"]);
      data.GetLong("ConversionStatus", status);
      r["conversion_status"] = INTEGER(status);
      data.GetLong("ProtectionStatus", status);
      r["protection_status"] = INTEGER(status);
      results.push_back(r);
    }
  } else {
    r["device_id"] = "-1";
    r["drive_letter"] = "-1";
    r["persistent_volume_id"] = "-1";
    r["conversion_status"] = "-1";
    r["protection_status"] = "-1";
  }

  return results;
}
} // namespace tables
} // namespace osquery