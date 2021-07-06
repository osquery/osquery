/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/CustomCapability/Service/Client/uefi.cpp

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>

#include <windows.h>

namespace osquery {
namespace tables {

int readBoolEfiVar(char* guid, char* name) {
  BYTE variableStatus;
  auto bytesReturned =
      GetFirmwareEnvironmentVariable(name, guid, &variableStatus, sizeof(BYTE));

  if (bytesReturned <= 0) {
    TLOG << "Unable to get EFI variable " << name
         << ". Error: " << std::to_string(GetLastError());
    return -1;
  }

  if (bytesReturned != sizeof(BYTE)) {
    TLOG << "Unable to get EFI variable " << name << ". ERROR_INVALID_DATA";
    return -1;
  }

  if (secureBootStatus == 0) {
    return 0;
  }

  return 1;
}

QueryData genSecureBoot(QueryContext& context) {
  QueryData results;

  Row r;
  r["secure_boot"] = readBoolEfiVar(kBootGUID, kSecureBootName);
  r["setup_mode"] = readBoolEfiVar(kBootGUID, kSetupModeName);

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
