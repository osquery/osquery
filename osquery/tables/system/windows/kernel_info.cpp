/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <Windows.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

std::string kNtKernelPath =
    (getSystemRoot() / "System32\\ntoskrnl.exe").string();

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
  char buf[51] = {0};
  auto sysRoot = getSystemRoot().root_name().string() + "\\";
  if (GetVolumeNameForVolumeMountPoint(
          sysRoot.c_str(), static_cast<LPSTR>(buf), 50)) {
    r["device"] = SQL_TEXT(buf);
  }
}

void GetKernelVersion(Row& r) {
  unsigned int size = 0;
  auto verSize = GetFileVersionInfoSize(kNtKernelPath.c_str(), nullptr);
  if (verSize == 0) {
    TLOG << "GetFileVersionInfoSize failed (" << GetLastError() << ")";
    return;
  }

  auto verData = static_cast<LPSTR>(malloc(verSize));

  if (!GetFileVersionInfo(kNtKernelPath.c_str(), 0, verSize, verData)) {
    TLOG << "GetFileVersionInfo failed (" << GetLastError() << ")";
  }

  void* vptrVersionInfo = nullptr;
  if (!VerQueryValue(verData, "\\", &vptrVersionInfo, &size)) {
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

  r["path"] = SQL_TEXT(getSystemRoot().string() + "\\System32\\ntoskrnl.exe");

  return {r};
}
} // namespace tables
} // namespace osquery
