/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <Windows.h>

#include "osquery/tables/system/windows/registry.h"
#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#pragma comment(lib, "version.lib")

namespace osquery {
namespace tables {

void GetBootArgs(Row& r) {
  QueryData regResults;
  queryKey(
      "HKEY_LOCAL_MACHINE", "SYSTEM\\CurrentControlSet\\Control", regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "SystemStartOptions") {
      r["arguments"] = SQL_TEXT(aKey.at("data"));
    }
  }
}

void GetSystemDriveGUID(Row& r) {
  char buf[50];
  std::string sysRoot = getSystemRoot().root_name().string() + "\\";
  if (GetVolumeNameForVolumeMountPoint(sysRoot.c_str(), (LPSTR)buf, 50)) {
    r["device"] = SQL_TEXT(buf);
  }
}

void GetKernelVersion(Row& r) {
  const LPCSTR kNtKernelPath = "C:\\Windows\\System32\\NTOSKRNL.EXE";
  DWORD verHandle = NULL;
  UINT size = 0;
  VS_FIXEDFILEINFO* lpVersionInfo = NULL;
  DWORD verSize = 0;

  verSize = GetFileVersionInfoSize(kNtKernelPath, &verHandle);
  if (verSize == 0) {
    TLOG << "GetFileVersionInfoSize failed (" << GetLastError() << ")";
    return;
  }

  LPSTR verData = (LPSTR)malloc(verSize);

  if (!GetFileVersionInfo(kNtKernelPath, verHandle, verSize, verData)) {
    TLOG << "GetFileVersionInfo failed (" << GetLastError() << ")";
  }

  if (!VerQueryValue(verData, "\\", (LPVOID*)&lpVersionInfo, &size)) {
    TLOG << "GetFileVersionInfo failed (" << GetLastError() << ")";
  }

  if (size) {
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
}
}
