/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for security_profile_info
// Spec file: specs/windows/security_profile_info.table

#include <osquery/tables/system/windows/security_profile_info_utils.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class WindowsSecurityProfileTests : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(WindowsSecurityProfileTests, test_sanity_profile_info) {
  // Sanity check to ensure that test only runs if this is not a WoW64 process
  if (!osquery::tables::SceClientHelper::isWow64Process()) {
    auto const data = execute_query("select * from security_profile_info");

    ValidationMap rowMap = {
        {"minimum_password_age", IntType | NonEmpty | NonNull},
        {"maximum_password_age", IntType | NonEmpty | NonNull},
        {"minimum_password_length", IntType | NonEmpty | NonNull},
        {"password_complexity", IntType | NonEmpty | NonNull},
        {"password_history_size", IntType | NonEmpty | NonNull},
        {"lockout_bad_count", IntType | NonEmpty | NonNull},
        {"logon_to_change_password", IntType | NonEmpty | NonNull},
        {"force_logoff_when_expire", IntType | NonEmpty | NonNull},
        {"new_administrator_name", EmptyOk},
        {"new_guest_name", EmptyOk},
        {"clear_text_password", IntType | NonEmpty | NonNull},
        {"lsa_anonymous_name_lookup", IntType | NonEmpty | NonNull},
        {"enable_admin_account", IntType | NonEmpty | NonNull},
        {"enable_guest_account", IntType | NonEmpty | NonNull},
        {"audit_system_events", IntType | NonEmpty | NonNull},
        {"audit_logon_events", IntType | NonEmpty | NonNull},
        {"audit_object_access", IntType | NonEmpty | NonNull},
        {"audit_privilege_use", IntType | NonEmpty | NonNull},
        {"audit_policy_change", IntType | NonEmpty | NonNull},
        {"audit_account_manage", IntType | NonEmpty | NonNull},
        {"audit_process_tracking", IntType | NonEmpty | NonNull},
        {"audit_ds_access", IntType | NonEmpty | NonNull},
        {"audit_account_logon", IntType | NonEmpty | NonNull},
    };

    validate_rows(data, rowMap);
  }
}

} // namespace table_tests
} // namespace osquery
