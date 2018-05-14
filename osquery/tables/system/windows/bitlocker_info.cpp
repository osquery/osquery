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

#define DECLARE_TABLE_IMPLEMENTATION_bitlocker_info
#include <generated/tables/tbl_bitlocker_info_defs.hpp>

namespace osquery {
namespace tables {

QueryData genBitlockerInfo(QueryContext& context) {
  Row r;
  QueryData results;

  WmiRequest wmiSystemReq(
      "SELECT * FROM Win32_EncryptableVolume",
      (BSTR)L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (wmiResults.empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }
  for (const auto& data : wmiResults) {
    long status = 0;
    long emethod;
    data.GetString("DeviceID", r["device_id"]);
    data.GetString("DriveLetter", r["drive_letter"]);
    data.GetString("PersistentVolumeID", r["persistent_volume_id"]);
    data.GetLong("ConversionStatus", status);
    r["conversion_status"] = INTEGER(status);
    data.GetLong("ProtectionStatus", status);
    r["protection_status"] = INTEGER(status);
    data.GetLong("EncryptionMethod", emethod);
    std::string emethod_str;
    std::map<long, std::string> methods;

    methods[0] = "None";
    methods[1] = "AES_128_WITH_DIFFUSER";
    methods[2] = "AES_256_WITH_DIFFUSER";
    methods[3] = "AES_128";
    methods[4] = "AES_256";
    methods[5] = "HARDWARE_ENCRYPTION";
    methods[6] = "XTS_AES_128";
    methods[7] = "XTS_AES_256";

    if (methods.find(emethod) != methods.end()) {
      emethod_str = methods.find(emethod)->second;
    } else {
      emethod_str = "UNKNOWN";
    }
    r["encryption_method"] = emethod_str;
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery