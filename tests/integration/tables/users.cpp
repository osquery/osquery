/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for users
// Spec file: specs/users.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {
namespace {

class UsersTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(UsersTest, test_sanity) {
  auto const rows = execute_query("select * from users");
  ASSERT_GE(rows.size(), 1ul); // There must be at least one user
  auto row_map = ValidatatioMap{
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
  } else {
    row_map.emplace("uuid", NormalType);
  }
  validate_rows(rows, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
