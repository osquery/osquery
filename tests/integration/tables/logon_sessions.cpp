/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for logon_sessions
// Spec file: specs/windows/logon_sessions.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class logonSessions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(logonSessions, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from logon_sessions");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"logon_id", IntType}
  //      {"user", NormalType}
  //      {"logon_domain", NormalType}
  //      {"authentication_package", NormalType}
  //      {"logon_type", NormalType}
  //      {"session_id", IntType}
  //      {"logon_sid", NormalType}
  //      {"logon_time", IntType}
  //      {"logon_server", NormalType}
  //      {"dns_domain_name", NormalType}
  //      {"upn", NormalType}
  //      {"logon_script", NormalType}
  //      {"profile_path", NormalType}
  //      {"home_directory", NormalType}
  //      {"home_directory_drive", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
