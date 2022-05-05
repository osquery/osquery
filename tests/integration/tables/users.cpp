/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for users
// Spec file: specs/users.table

#include <string>

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

#ifdef OSQUERY_WINDOWS
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/users_service.h>
#endif

namespace osquery {
namespace table_tests {

class UsersTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    // For the users table we need to start services
    // to fill up the caches
    std::promise<void> users_cache_promise;
    GlobalUsersGroupsCache::global_users_cache_future_ =
        users_cache_promise.get_future();

    Dispatcher::addService(std::make_shared<UsersService>(
        std::move(users_cache_promise),
        GlobalUsersGroupsCache::global_users_cache_));
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    GlobalUsersGroupsCache::global_users_cache_->clear();
    Dispatcher::instance().resetStopping();
  }
#endif
};

TEST_F(UsersTest, test_sanity) {
  auto row_map = ValidationMap{
      {"uid", NonNegativeInt},
      {"uid_signed", IntType},
      {"gid_signed", IntType},
      {"description", NormalType},
      {"shell", NonEmptyString},
  };
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("gid", IntType);
    row_map.emplace("username", NormalType);
  } else {
    row_map.emplace("gid", NonNegativeInt);
    row_map.emplace("username", NonEmptyString);
  }
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("directory", NormalType);
  } else {
    row_map.emplace("directory", NonEmptyString);
  }
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("type", NormalType);
  }
  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("uuid", ValidUUID);
    row_map.emplace("is_hidden", IntType);
  } else {
    row_map.emplace("uuid", NormalType);
  }

  // select * case
  auto const rows = execute_query("select * from users");
  ASSERT_GE(rows.size(), 1ul);
  validate_rows(rows, row_map);

  // select with a specified uid
  auto test_uid = rows.front().at("uid");
  auto const rows_one =
      execute_query(std::string("select * from users where uid=") + test_uid);
  ASSERT_GE(rows_one.size(), 1ul);
  validate_rows(rows_one, row_map);
}

} // namespace table_tests
} // namespace osquery
