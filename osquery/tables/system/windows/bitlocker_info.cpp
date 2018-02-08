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

  WmiRequest wmiSystemReq("SELECT * FROM Win32_EncryptableVolume",
                          L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (!wmiResults.empty()) {
    long protectionstatus = 0;
    wmiResults[0].GetString("DeviceID", r["device_id"]);
    wmiResults[0].GetString("DriveLetter", r["drive_letter"]);
    wmiResults[0].GetString("PersistentVolumeID", r["persistent_volume_id"]);
    wmiResults[0].GetLong("ConversionStatus", protectionstatus);
    r["conversion_status"] = INTEGER(protectionstatus);
    wmiResults[0].GetLong("ProtectionStatus", protectionstatus);
    r["protection_status"] = INTEGER(protectionstatus);
  } else {
    r["device_id"] = "-1";
    r["drive_letter"] = "-1";
    r["persistent_volume_id"] = "-1";
    r["conversion_status"] = "-1";
    r["protection_status"] = "-1";
  }

  results.push_back(r);
  return results;
}
}
}