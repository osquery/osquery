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

#include <osquery/tests/integration/tables/helper.h>

#ifdef OSQUERY_WINDOWS
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/groups_service.h>
#include <osquery/system/usersgroups/windows/users_service.h>
#endif

namespace osquery {
namespace table_tests {

class UserGroups : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    // For the users table we need to start services
    // to fill up the caches
    std::promise<void> users_cache_promise;
    std::promise<void> groups_cache_promise;
    GlobalUsersGroupsCache::global_users_cache_future_ =
        users_cache_promise.get_future();
    GlobalUsersGroupsCache::global_groups_cache_future_ =
        groups_cache_promise.get_future();

    Dispatcher::addService(std::make_shared<UsersService>(
        std::move(users_cache_promise),
        GlobalUsersGroupsCache::global_users_cache_));

    Dispatcher::addService(std::make_shared<GroupsService>(
        std::move(groups_cache_promise),
        GlobalUsersGroupsCache::global_groups_cache_));
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    GlobalUsersGroupsCache::global_users_cache_->clear();
    GlobalUsersGroupsCache::global_groups_cache_->clear();
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
