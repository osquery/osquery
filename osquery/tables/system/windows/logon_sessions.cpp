// clang-format off
#include <Windows.h>
#include <sddl.h>
#include <tchar.h>
#include <vector>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/process_ops.h"
// clang-format on

#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))

namespace osquery {
namespace tables {
typedef LONG NTSTATUS;

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef struct _LSA_LAST_INTER_LOGON_INFO {
  LARGE_INTEGER LastSuccessfulLogon;
  LARGE_INTEGER LastFailedLogon;
  ULONG FailedAttemptCountSinceLastSuccessfulLogon;
} LSA_LAST_INTER_LOGON_INFO, *PLSA_LAST_INTER_LOGON_INFO;

typedef struct _SECURITY_LOGON_SESSION_DATA {
  ULONG Size;
  LUID LogonId;
  LSA_UNICODE_STRING UserName;
  LSA_UNICODE_STRING LogonDomain;
  LSA_UNICODE_STRING AuthenticationPackage;
  ULONG LogonType;
  ULONG Session;
  PSID Sid;
  LARGE_INTEGER LogonTime;
  LSA_UNICODE_STRING LogonServer;
  LSA_UNICODE_STRING DnsDomainName;
  LSA_UNICODE_STRING Upn;
  ULONG UserFlags;
  LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
  LSA_UNICODE_STRING LogonScript;
  LSA_UNICODE_STRING ProfilePath;
  LSA_UNICODE_STRING HomeDirectory;
  LSA_UNICODE_STRING HomeDirectoryDrive;
  LARGE_INTEGER LogoffTime;
  LARGE_INTEGER KickOffTime;
  LARGE_INTEGER PasswordLastSet;
  LARGE_INTEGER PasswordCanChange;
  LARGE_INTEGER PasswordMustChange;
} SECURITY_LOGON_SESSION_DATA, *PSECURITY_LOGON_SESSION_DATA;

LONGLONG filetimeToUnixtime(const LARGE_INTEGER& ft) {
  LARGE_INTEGER date, adjust;
  date.HighPart = ft.HighPart;
  date.LowPart = ft.LowPart;
  adjust.QuadPart = 11644473600000 * 10000;
  date.QuadPart -= adjust.QuadPart;
  return date.QuadPart / 10000000;
}

LPTSTR GetLogonType(ULONG logonType) {
  switch (logonType) {
  case 2:
    return TEXT("Interactive");
  case 3:
    return TEXT("Network");
  case 4:
    return TEXT("Batch");
  case 5:
    return TEXT("Service");
  case 6:
    return TEXT("Proxy");
  case 7:
    return TEXT("Unlock");
  case 8:
    return TEXT("NetworkCleartext");
  case 9:
    return TEXT("NewCredentials");
  case 10:
    return TEXT("RemoteInteractive");
  case 11:
    return TEXT("CachedInteractive");
  case 12:
    return TEXT("CachedRemoteInteractive");
  case 13:
    return TEXT("CachedUnlock");
  default:
    return TEXT("None");
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

    for (size_t i = 0; i < sessionCount; i++) {
      PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
      NTSTATUS status = LsaGetLogonSessionData(&sessions[i], &sessionData);

      // I need to go back and convert LARGE_INTEGER values to Unix Timestamp
      if (status == 0) {
        Row r;
        r["logon_id"] = INTEGER(sessionData->LogonId.LowPart);
        r["user"] = wstringToString(sessionData->UserName.Buffer);
        r["logon_domain"] = wstringToString(sessionData->LogonDomain.Buffer);
        r["authentication_package"] =
            wstringToString(sessionData->AuthenticationPackage.Buffer);
        r["logon_type"] = GetLogonType(sessionData->LogonType);
        r["session_id"] = INTEGER(sessionData->Session);
        LPTSTR sid;
        ConvertSidToStringSid(sessionData->Sid, &sid);
        r["logon_sid"] = sid;
        r["logon_time"] = BIGINT(filetimeToUnixtime(sessionData->LogonTime));
        r["logon_server"] = wstringToString(sessionData->LogonServer.Buffer);
        r["dns_domain_name"] =
            wstringToString(sessionData->DnsDomainName.Buffer);
        //r["upn"] = wstringToString(sessionData->Upn.Buffer);
        r["upn"] = INTEGER(sessionData->Upn.Length);
        /*
				r["user_flags"] = INTEGER(sessionData->UserFlags); 
				r["last_successful_logon"] = BIGINT(
            filetimeToUnixtime(sessionData->LastLogonInfo.LastSuccessfulLogon));
        r["last_failed_logon"] = BIGINT(
            filetimeToUnixtime(sessionData->LastLogonInfo.LastFailedLogon));
        r["failed_attempt_count_since_last_successful_logon"] =
            INTEGER(sessionData->LastLogonInfo
                        .FailedAttemptCountSinceLastSuccessfulLogon);
        */
				r["logon_script"] = wstringToString(sessionData->LogonScript.Buffer);
        r["profile_path"] = wstringToString(sessionData->ProfilePath.Buffer);
        r["home_directory"] =
            wstringToString(sessionData->HomeDirectory.Buffer);
        r["home_directory_drive"] =
            wstringToString(sessionData->HomeDirectoryDrive.Buffer);
        /*
				r["logoff_time"] = BIGINT(filetimeToUnixtime(sessionData->LogoffTime));
        r["kick_off_time"] =
            BIGINT(filetimeToUnixtime(sessionData->KickOffTime));
        r["password_last_set"] =
            BIGINT(filetimeToUnixtime(sessionData->PasswordLastSet));
        r["password_can_change"] =
            BIGINT(filetimeToUnixtime(sessionData->PasswordCanChange));
        r["password_must_change"] =
            BIGINT(filetimeToUnixtime(sessionData->PasswordMustChange));
        */
				results.push_back(r);
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