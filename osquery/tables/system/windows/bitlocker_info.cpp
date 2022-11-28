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
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

static void fetchMethodResultLong(std::string& result,
                                  const WmiRequest& req,
                                  const WmiResultItem& object,
                                  const std::string& method,
                                  const std::string& param) {
  WmiMethodArgs args;
  WmiResultItem out;

  auto status = req.ExecMethod(object, method, args, out);
  if (status.ok()) {
    long value = -1;
    status = out.GetLong(param, value);
    if (status.ok()) {
      result = INTEGER(value);
    } else {
      result = INTEGER(-1);
    }
  } else {
    result = INTEGER(-1);
  }
}

QueryData genBitlockerInfo(QueryContext& context) {
  Row r;
  QueryData results;

  const Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest(
          "SELECT * FROM Win32_EncryptableVolume",
          (BSTR)L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();
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

    fetchMethodResultLong(
        r["version"], *wmiSystemReq, data, "GetVersion", "Version");
    fetchMethodResultLong(r["percentage_encrypted"],
                          *wmiSystemReq,
                          data,
                          "GetConversionStatus",
                          "EncryptionPercentage");
    fetchMethodResultLong(
        r["lock_status"], *wmiSystemReq, data, "GetLockStatus", "LockStatus");

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
