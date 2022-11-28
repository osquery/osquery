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

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class UsersTest : public testing::Test {
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
