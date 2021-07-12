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
#include <osquery/utils/conversions/windows/strings.h>

#include <windows.h>

namespace osquery {
namespace tables {

// convert to the windows LPWSTR format
const auto kEFISecureBootNameLPWSTR = stringToWstring(kEFISecureBootName);
const auto kEFISetupModeNameLPWSTR = stringToWstring(kEFISetupModeName);

int readBoolEfiVar(std::wstring guid, std::wstring name) {
  BYTE res;
  auto bytesReturned = GetFirmwareEnvironmentVariable(
      name.c_str(), guid.c_str(), &res, sizeof(res));

  if (bytesReturned <= 0) {
    auto lastError = GetLastError();
    // FIXME: Consider not logging here. The no bios support is probably common
    auto errorString = lastError == 1 ? "Probably no bios support"
                                      : errorDwordToString(lastError);

    TLOG << "Unable to get EFI variable " << wstringToString(name).c_str()
         << ". Error: " << errorString;
    // FIXME: Consider returning NULL instead?
    return -1;
  }

  if (bytesReturned != sizeof(BYTE)) {
    TLOG << "Unable to get EFI variable " << wstringToString(name).c_str()
         << ". ERROR_INVALID_DATA";
    // FIXME: Consider returning NULL instead?
    return -1;
  }

  if (res == 0) {
    return 0;
  }

  return 1;
}

QueryData genSecureBoot(QueryContext& context) {
  QueryData results;

  Row r;
  r["secure_boot"] =
      INTEGER(readBoolEfiVar(kEFIBootGUIDwin, kEFISecureBootNameLPWSTR));
  r["setup_mode"] =
      INTEGER(readBoolEfiVar(kEFIBootGUIDwin, kEFISetupModeNameLPWSTR));

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
