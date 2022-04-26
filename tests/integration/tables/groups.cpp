/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for groups
// Spec file: specs/groups.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>
#ifdef OSQUERY_WINDOWS
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/groups_service.h>
#endif

namespace osquery {
namespace table_tests {

class groups : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    // For the groups table we need to start services
    // to fill up the caches
    std::promise<void> groups_cache_promise;
    GlobalUsersGroupsCache::global_groups_cache_future_ =
        groups_cache_promise.get_future();

    Dispatcher::addService(std::make_shared<GroupsService>(
        std::move(groups_cache_promise),
        GlobalUsersGroupsCache::global_groups_cache_));
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    GlobalUsersGroupsCache::global_groups_cache_->clear();
    Dispatcher::instance().resetStopping();
  }
#endif
};

TEST_F(groups, test_sanity) {
  // Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  ValidationMap row_map = {
      {"gid", IntType},
      {"gid_signed", IntType},
      {"groupname", NormalType},
  };

  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("is_hidden", IntType);
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("comment", NormalType);
    row_map.emplace("group_sid", NormalType);
  }

  // select * case
  auto const rows = execute_query("select * from groups");
  ASSERT_GE(rows.size(), 1ul);
  validate_rows(rows, row_map);

  // select with a specific gid
  auto test_gid = rows.front().at("gid");
  auto const rows_one =
      execute_query(std::string("select * from groups where gid=") + test_gid);
  ASSERT_GE(rows_one.size(), 1ul);
  validate_rows(rows_one, row_map);
}

} // namespace table_tests
} // namespace osquery
