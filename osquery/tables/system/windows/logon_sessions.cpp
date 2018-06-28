// clang-format off
#include <Windows.h>
#include <NTSecAPI.h>
#include <sddl.h>
#include <tchar.h>
#include <vector>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/process_ops.h"
// clang-format on

#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))
#define JAN_1_1601_TO_JAN_1_1970 116444736000000000
#define HUNDREDNANOSECONDS_TO_SECONDS 10000000

namespace osquery {
namespace tables {
LONGLONG filetimeToUnixtime(const LARGE_INTEGER& ft) {
  LARGE_INTEGER date, adjust;
  date.HighPart = ft.HighPart;
  date.LowPart = ft.LowPart;
  adjust.QuadPart = JAN_1_1601_TO_JAN_1_1970;
  date.QuadPart -= adjust.QuadPart;
  return date.QuadPart / HUNDREDNANOSECONDS_TO_SECONDS;
}

LPWSTR GetLogonType(ULONG logonType) {
  switch (logonType) {
  case 2:
    return L"Interactive";
  case 3:
    return L"Network";
  case 4:
    return L"Batch";
  case 5:
    return L"Service";
  case 6:
    return L"Proxy";
  case 7:
    return L"Unlock";
  case 8:
    return L"NetworkCleartext";
  case 9:
    return L"NewCredentials";
  case 10:
    return L"RemoteInteractive";
  case 11:
    return L"CachedInteractive";
  case 12:
    return L"CachedRemoteInteractive";
  case 13:
    return L"CachedUnlock";
  default:
    return L"None";
  }
}

QueryData QueryLogonSessions(QueryContext& context) {
  QueryData results;
  bool loadedManually = false;

  HMODULE module = GetModuleHandle(TEXT("Secur32.dll"));

  if (!module) {
    module = LoadLibrary(TEXT("Secur32.dll"));
    loadedManually = true;
  }

  NTSTATUS(__stdcall * LsaEnumerateLogonSessions)
  (PULONG LogonSessionCount, PLUID * LogonSessionList);
  LsaEnumerateLogonSessions =
      reinterpret_cast<decltype(LsaEnumerateLogonSessions)>(
          GetProcAddress(module, "LsaEnumerateLogonSessions"));

  NTSTATUS(__stdcall * LsaGetLogonSessionData)
  (PLUID LogonId, PSECURITY_LOGON_SESSION_DATA * ppLogonSessionData);
  LsaGetLogonSessionData = reinterpret_cast<decltype(LsaGetLogonSessionData)>(
      GetProcAddress(module, "LsaGetLogonSessionData"));

  NTSTATUS(__stdcall * LsaFreeReturnBuffer)(PVOID Buffer);
  LsaFreeReturnBuffer = reinterpret_cast<decltype(LsaFreeReturnBuffer)>(
      GetProcAddress(module, "LsaFreeReturnBuffer"));

  if (LsaEnumerateLogonSessions && LsaGetLogonSessionData &&
      LsaFreeReturnBuffer) {
    PLUID sessions = NULL;
    ULONG sessionCount = 0;
    NTSTATUS status = LsaEnumerateLogonSessions(&sessionCount, &sessions);

    if (status == 0) {
      for (size_t i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        NTSTATUS status = LsaGetLogonSessionData(&sessions[i], &sessionData);

        if (status == 0) {
          Row r;
          r["logon_id"] = INTEGER(sessionData->LogonId.LowPart);
          r["user"] = wstringToString(sessionData->UserName.Buffer);
          r["logon_domain"] = wstringToString(sessionData->LogonDomain.Buffer);
          r["authentication_package"] =
              wstringToString(sessionData->AuthenticationPackage.Buffer);
          r["logon_type"] =
              wstringToString(GetLogonType(sessionData->LogonType));
          r["session_id"] = INTEGER(sessionData->Session);
          LPTSTR sid;
          if (ConvertSidToStringSid(sessionData->Sid, &sid)) {
            r["logon_sid"] = sid;
          }
          if (sid) {
            LocalFree(sid);
          }
          r["logon_time"] = BIGINT(filetimeToUnixtime(sessionData->LogoffTime));
          r["logon_server"] = wstringToString(sessionData->LogonServer.Buffer);
          r["dns_domain_name"] =
              wstringToString(sessionData->DnsDomainName.Buffer);
          r["upn"] = wstringToString(sessionData->Upn.Buffer);
          r["logon_script"] = wstringToString(sessionData->LogonScript.Buffer);
          r["profile_path"] = wstringToString(sessionData->ProfilePath.Buffer);
          r["home_directory"] =
              wstringToString(sessionData->HomeDirectory.Buffer);
          r["home_directory_drive"] =
              wstringToString(sessionData->HomeDirectoryDrive.Buffer);
          results.push_back(r);
        }
      }
    }

    if (sessions) {
      LsaFreeReturnBuffer(sessions);
    }
  }

  if (loadedManually) {
    FreeLibrary(module);
  }
  return results;
}
} // namespace tables
} // namespace osquery