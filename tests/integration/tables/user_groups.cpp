/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for user_groups
// Spec file: specs/user_groups.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class UserGroups : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, true);
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, true);
    Dispatcher::instance().resetStopping();
  }
#endif
};

TEST_F(UserGroups, test_sanity) {
  QueryData data = execute_query("select * from user_groups");
  ASSERT_GT(data.size(), 0ul);
  ValidationMap row_map = {{"uid", verifyUidGid}, {"gid", verifyUidGid}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
