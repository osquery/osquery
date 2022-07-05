/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for ssh_configs
// Spec file: specs/posix/ssh_configs.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class sshConfigs : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, false);
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, false);
    Dispatcher::instance().resetStopping();
  }
#endif
};

TEST_F(sshConfigs, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from ssh_configs");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"uid", IntType}
  //      {"block", NormalType}
  //      {"option", NormalType}
  //      {"ssh_config_file", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
