/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/security_profile_info_utils.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

QueryData genSecurityProfileInformation(QueryContext& context) {
  QueryData results;

  // Getting system security profile information
  SceProfileData data;
  const SceClientHelper::SceProfileInfo* profileData = data.getProfileInfo();
  if (profileData == nullptr) {
    LOG(ERROR) << "Failed to retrieve security profile information data.";
    return results;
  }

  // And then populating the table with obtained data
  Row seceditRow;
  seceditRow["minimum_password_age"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->MinPasswdAge));

  seceditRow["maximum_password_age"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->MaxPasswdAge));

  seceditRow["minimum_password_length"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->MinPasswdLen));

  seceditRow["password_complexity"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->PasswdComplexity));

  seceditRow["password_history_size"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->PasswdHistSize));

  seceditRow["lockout_bad_count"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->LockoutBadCount));

  seceditRow["logon_to_change_password"] = INTEGER(
      SceProfileData::getNormalizedInt(profileData->ReqLogonChangePasswd));

  seceditRow["force_logoff_when_expire"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->ForceLogoffExpire));

  seceditRow["new_administrator_name"] =
      wstringToString(profileData->AdministratorName);

  seceditRow["new_guest_name"] = wstringToString(profileData->GuestName);

  seceditRow["clear_text_password"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->ClearTextPasswd));

  seceditRow["lsa_anonymous_name_lookup"] =
      INTEGER(SceProfileData::getNormalizedInt(
          profileData->LsaAllowAnonymousSidLookup));

  seceditRow["enable_admin_account"] = INTEGER(
      SceProfileData::getNormalizedInt(profileData->EnableAdminAccount));

  seceditRow["enable_guest_account"] = INTEGER(
      SceProfileData::getNormalizedInt(profileData->EnableGuestAccount));

  seceditRow["audit_system_events"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->AuditSystemEvents));

  seceditRow["audit_logon_events"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->AuditLogonEvents));

  seceditRow["audit_object_access"] = INTEGER(
      SceProfileData::getNormalizedInt(profileData->AuditObjectsAccess));

  seceditRow["audit_privilege_use"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->AuditPrivilegeUse));

  seceditRow["audit_policy_change"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->AuditPolicyChange));

  seceditRow["audit_account_manage"] = INTEGER(
      SceProfileData::getNormalizedInt(profileData->AuditAccountManage));

  seceditRow["audit_process_tracking"] = INTEGER(
      SceProfileData::getNormalizedInt(profileData->AuditProcessTracking));

  seceditRow["audit_ds_access"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->AuditDSAccess));

  seceditRow["audit_account_logon"] =
      INTEGER(SceProfileData::getNormalizedInt(profileData->AuditAccountLogon));

  results.push_back(std::move(seceditRow));

  return results;
}

} // namespace tables
} // namespace osquery
