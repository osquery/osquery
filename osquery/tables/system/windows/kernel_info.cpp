/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/system.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

std::wstring kNtKernelPath =
    (getSystemRoot() / L"System32\\ntoskrnl.exe").wstring();

void GetBootArgs(Row& r) {
  QueryData regResults;
  queryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control",
           regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "SystemStartOptions") {
      r["arguments"] = SQL_TEXT(aKey.at("data"));
    }
  }
}

void GetSystemDriveGUID(Row& r) {
  WCHAR buf[51] = {0};
  auto sysRoot = getSystemRoot().root_name().wstring() + L"\\";
  if (GetVolumeNameForVolumeMountPoint(
          sysRoot.c_str(), static_cast<LPWSTR>(buf), 50)) {
    r["device"] = SQL_TEXT(wstringToString(buf));
  }
}

void GetKernelVersion(Row& r) {
  unsigned int size = 0;
  auto verSize = GetFileVersionInfoSizeW(kNtKernelPath.c_str(), nullptr);
  if (verSize == 0) {
    TLOG << "GetFileVersionInfoSize failed (" << GetLastError() << ")";
    return;
  }

  auto verData = static_cast<LPWSTR>(malloc(verSize));

  if (!GetFileVersionInfoW(kNtKernelPath.c_str(), 0, verSize, verData)) {
    TLOG << "GetFileVersionInfo failed (" << GetLastError() << ")";
  }

  void* vptrVersionInfo = nullptr;
  if (!VerQueryValueW(verData, L"\\", &vptrVersionInfo, &size)) {
    TLOG << "GetFileVersionInfo failed (" << GetLastError() << ")";
  }
  auto lpVersionInfo = static_cast<VS_FIXEDFILEINFO*>(vptrVersionInfo);
  if (size > 0) {
    if (lpVersionInfo->dwSignature == 0xfeef04bd) {
      auto majorMS = HIWORD(lpVersionInfo->dwProductVersionMS);
      auto minorMS = LOWORD(lpVersionInfo->dwProductVersionMS);
      auto majorLS = HIWORD(lpVersionInfo->dwProductVersionLS);
      auto minorLS = LOWORD(lpVersionInfo->dwProductVersionLS);

      r["version"] = SQL_TEXT(
          std::to_string(majorMS) + "." + std::to_string(minorMS) + "." +
          std::to_string(majorLS) + "." + std::to_string(minorLS));
    } else {
      TLOG << "Incorrect Version Signature (" << GetLastError() << ")";
    }

  } else {
    TLOG << "No Version information (" << GetLastError() << ")";
  }

  free(verData);
}

QueryData genKernelInfo(QueryContext& context) {
  Row r;
  GetKernelVersion(r);
  GetBootArgs(r);
  GetSystemDriveGUID(r);

  r["path"] = SQL_TEXT(
      wstringToString(getSystemRoot().wstring() + L"\\System32\\ntoskrnl.exe"));

  return {r};
}
} // namespace tables
} // namespace osquery
