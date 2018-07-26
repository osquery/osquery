/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// clang-format is turned off to ensure windows.h is first
// clang-format off
#include <Windows.h>
// clang-format on
#include <NTSecAPI.h>
#include <sddl.h>
#include <tchar.h>
#include <vector>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/process_ops.h"
#include "osquery/filesystem/fileops.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

namespace osquery {
namespace tables {
static const std::unordered_map<SECURITY_LOGON_TYPE, std::string>
    kLogonTypeToStr = {{UndefinedLogonType, "Undefined Logon Type"},
                       {Interactive, "Interactive"},
                       {Network, "Network"},
                       {Batch, "Batch"},
                       {Service, "Service"},
                       {Proxy, "Proxy"},
                       {Unlock, "Unlock"},
                       {NetworkCleartext, "Network Cleartext"},
                       {NewCredentials, "New Credentials"},
                       {RemoteInteractive, "Remote Interactive"},
                       {CachedInteractive, "Cached Interactive"},
                       {CachedRemoteInteractive, "Cached Remote Interactive"},
                       {CachedUnlock, "Cached Unlock"}};

QueryData queryLogonSessions(QueryContext& context) {
  ULONG session_count = 0;
  PLUID sessions = nullptr;
  NTSTATUS status = LsaEnumerateLogonSessions(&session_count, &sessions);

  QueryData results;
  if (status == STATUS_SUCCESS) {
    for (ULONG i = 0; i < session_count; i++) {
      PSECURITY_LOGON_SESSION_DATA session_data = NULL;
      NTSTATUS status = LsaGetLogonSessionData(&sessions[i], &session_data);
      if (status != STATUS_SUCCESS) {
        continue;
      }

      Row r;
      r["logon_id"] = INTEGER(session_data->LogonId.LowPart);
      r["user"] = wstringToString(session_data->UserName.Buffer);
      r["logon_domain"] = wstringToString(session_data->LogonDomain.Buffer);
      r["authentication_package"] =
          wstringToString(session_data->AuthenticationPackage.Buffer);
      r["logon_type"] =
          kLogonTypeToStr.find(SECURITY_LOGON_TYPE(session_data->LogonType))
              ->second;
      r["session_id"] = INTEGER(session_data->Session);
      LPTSTR sid = nullptr;
      if (ConvertSidToStringSid(session_data->Sid, &sid)) {
        r["logon_sid"] = sid;
      }
      if (sid) {
        LocalFree(sid);
      }
      r["logon_time"] = BIGINT(longIntToUnixtime(session_data->LogonTime));
      r["logon_server"] = wstringToString(session_data->LogonServer.Buffer);
      r["dns_domain_name"] =
          wstringToString(session_data->DnsDomainName.Buffer);
      r["upn"] = wstringToString(session_data->Upn.Buffer);
      r["logon_script"] = wstringToString(session_data->LogonScript.Buffer);
      r["profile_path"] = wstringToString(session_data->ProfilePath.Buffer);
      r["home_directory"] = wstringToString(session_data->HomeDirectory.Buffer);
      r["home_directory_drive"] =
          wstringToString(session_data->HomeDirectoryDrive.Buffer);
      results.push_back(std::move(r));
    }
  }
  return results;
} // function queryLogonSessions
} // namespace tables
} // namespace osquery