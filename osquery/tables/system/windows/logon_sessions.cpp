/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format is turned off to ensure windows.h is first
// clang-format off
#include <osquery/utils/system/system.h>
// clang-format on
#include <NTSecAPI.h>
#include <sddl.h>
#include <tchar.h>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

namespace osquery {
namespace tables {

ULONG kLsaStatusSuccess = 0;
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
  if (status == kLsaStatusSuccess) {
    for (ULONG i = 0; i < session_count; i++) {
      PSECURITY_LOGON_SESSION_DATA session_data = NULL;
      NTSTATUS status = LsaGetLogonSessionData(&sessions[i], &session_data);
      if (status != kLsaStatusSuccess) {
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
      r["logon_sid"] = psidToString(session_data->Sid);
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
