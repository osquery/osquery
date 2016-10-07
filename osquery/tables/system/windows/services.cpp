
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winsvc.h>
#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#pragma comment(lib, "Advapi32.lib")

namespace osquery {
namespace tables {

const std::string kSvcStartType[] = {
    "BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"};

const std::string kSvcStatus[] = {"UNKNOWN",
                                  "STOPPED",
                                  "START_PENDING",
                                  "STOP_PENDING",
                                  "RUNNING",
                                  "CONTINUE_PENDING",
                                  "PAUSE_PENDING",
                                  "PAUSED"};

const std::map<int, std::string> kServiceType = {
    {0x00000010, "OWN_PROCESS"},
    {0x00000020, "SHARE_PROCESS"},
    {0x00000100, "INTERACTIVE_PROCESS"},
    {0x00000110, "OWN_PROCESS   (Interactive)"},
    {0x00000120, "SHARE_PROCESS (Interactive)"}};

SC_HANDLE schSCManager;

BOOL QuerySvcInfo(ENUM_SERVICE_STATUS_PROCESS& svc, Row& r) {
  SC_HANDLE schService;
  LPQUERY_SERVICE_CONFIG lpsc = nullptr;
  LPSERVICE_DESCRIPTION lpsd = nullptr;
  DWORD cbBufSize = 0;

  schService =
      OpenService(schSCManager, svc.lpServiceName, SERVICE_QUERY_CONFIG);

  if (schService == NULL) {
    TLOG << "OpenService failed (" << GetLastError() << ")";
    return FALSE;
  }

  (void)QueryServiceConfig(schService, NULL, 0, &cbBufSize);
  lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
  if (!QueryServiceConfig(schService, lpsc, cbBufSize, &cbBufSize)) {
    TLOG << "QueryServiceConfig failed (" << GetLastError() << ")";
  }

  (void)QueryServiceConfig2(
      schService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &cbBufSize);
  lpsd = (LPSERVICE_DESCRIPTION)LocalAlloc(LMEM_FIXED, cbBufSize);
  if (!QueryServiceConfig2(schService,
                           SERVICE_CONFIG_DESCRIPTION,
                           (LPBYTE)lpsd,
                           cbBufSize,
                           &cbBufSize)) {
    TLOG << "QueryServiceConfig2 failed (" << GetLastError() << ")";
  }

  r["name"] = SQL_TEXT(svc.lpServiceName);
  r["display_name"] = SQL_TEXT(svc.lpDisplayName);
  r["status"] = SQL_TEXT(kSvcStatus[svc.ServiceStatusProcess.dwCurrentState]);
  r["pid"] = INTEGER(svc.ServiceStatusProcess.dwProcessId);
  r["win32_exit_code"] = INTEGER(svc.ServiceStatusProcess.dwWin32ExitCode);
  r["service_exit_code"] =
      INTEGER(svc.ServiceStatusProcess.dwServiceSpecificExitCode);
  r["start_type"] = SQL_TEXT(kSvcStartType[lpsc->dwStartType]);
  r["path"] = SQL_TEXT(lpsc->lpBinaryPathName);
  r["user_account"] = SQL_TEXT(lpsc->lpServiceStartName);

  if (lpsd->lpDescription != NULL)
    r["description"] = SQL_TEXT(lpsd->lpDescription);

  if (kServiceType.count(lpsc->dwServiceType) > 0)
    r["service_type"] = SQL_TEXT(kServiceType.at(lpsc->dwServiceType));
  else
    r["service_type"] = SQL_TEXT("UNKNOWN");

  LocalFree(lpsc);
  LocalFree(lpsd);
  CloseServiceHandle(schService);
  return TRUE;
}

QueryData genServices(QueryContext& context) {
  void* buf = NULL;
  DWORD BytesNeeded = 0;
  DWORD serviceCount = 0;
  Row r;
  QueryData results;

  schSCManager = OpenSCManagerW(NULL, NULL, GENERIC_READ);
  if (schSCManager == NULL) {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
    return {};
  }

  (void)EnumServicesStatusEx(schSCManager,
                             SC_ENUM_PROCESS_INFO,
                             SERVICE_WIN32,
                             SERVICE_STATE_ALL,
                             NULL,
                             0,
                             &BytesNeeded,
                             &serviceCount,
                             NULL,
                             NULL);

  buf = malloc(BytesNeeded);
  if (EnumServicesStatusEx(schSCManager,
                           SC_ENUM_PROCESS_INFO,
                           SERVICE_WIN32,
                           SERVICE_STATE_ALL,
                           (LPBYTE)buf,
                           BytesNeeded,
                           &BytesNeeded,
                           &serviceCount,
                           NULL,
                           NULL)) {
    ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)buf;
    for (DWORD i = 0; i < serviceCount; ++i) {
      if (QuerySvcInfo(services[i], r)) {
        results.push_back(r);
      }
      r.clear();
    }
  } else {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
  }

  free(buf);
  CloseServiceHandle(schSCManager);
  return results;
}
}
}
