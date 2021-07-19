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
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>
#include <osquery/utils/conversions/windows/strings.h>

#include <windows.h>

namespace osquery {
namespace tables {

// convert to the windows LPWSTR format
const auto kEFISecureBootNameLPWSTR = stringToWstring(kEFISecureBootName);
const auto kEFISetupModeNameLPWSTR = stringToWstring(kEFISetupModeName);

void readBoolEfiVar(Row& row,
                    std::string column_name,
                    std::wstring guid,
                    std::wstring name) {
  BYTE res;
  auto bytesReturned = GetFirmwareEnvironmentVariable(
      name.c_str(), guid.c_str(), &res, sizeof(res));

  if (bytesReturned <= 0) {
    auto lastError = GetLastError();
    // Error 1 is documented as probably meaning there's no bios
    // support. This is pretty common, just return
    if (lastError == 1) {
      return;
    }

    TLOG << "Unable to get EFI variable " << wstringToString(name).c_str()
         << ". Error: " << errorDwordToString(lastError);
    row.emplace(column_name, "-1");
  }

  if (bytesReturned != sizeof(BYTE)) {
    TLOG << "Unable to get EFI variable " << wstringToString(name).c_str()
         << ". ERROR_INVALID_DATA";
    row.emplace(column_name, "-1");
  }

  switch (res) {
  case 0:
    row.emplace(column_name, "0");
    break;
  case 1:
    row.emplace(column_name, "1");
    break;
  default:
    TLOG << "Unknown value in EFI variable " << wstringToString(name).c_str()
         << ". Got: " << res;
    row.emplace(column_name, "-1");
    break;
  }

  return;
}

QueryData genSecureBoot(QueryContext& context) {
  QueryData results;

  Row r;
  readBoolEfiVar(r, "secure_boot", kEFIBootGUIDwin, kEFISecureBootNameLPWSTR);
  readBoolEfiVar(r, "setup_mode", kEFIBootGUIDwin, kEFISetupModeNameLPWSTR);

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
