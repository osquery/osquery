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

namespace osquery {

class UsersTest : public IntegrationTableTest {};

TEST_F(UsersTest, sanity) {
  QueryData rows = execute_query("select * from users");
  ASSERT_GT(rows.size(), 0ul); // There must be at least one user
  auto row_map = ValidatatioMap{
      {"uid", NonNegativeInt},
      {"gid", NonNegativeInt},
      {"uid_signed", IntType},
      {"gid_signed", IntType},
      {"username", NonEmptyString},
      {"description", NormalType},
      {"directory", NonEmptyString}, // The directory path could be fake
      {"shell", FileOnDisk},
      {"uuid", ValidUUID},
#ifdef OSQUERY_WINDOWS
      {"type", NormalType},
#endif
  };
  validate_rows(rows, row_map);
}

} // namespace osquery
