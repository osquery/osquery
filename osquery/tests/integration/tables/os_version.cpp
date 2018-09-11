/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for os_version
// Spec file: specs/os_version.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class OsVersion : public IntegrationTableTest {};

TEST_F(OsVersion, test_sanity) {
  QueryData data = execute_query("select * from os_version");

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
      {"name", NonEmptyString},
      {"version", NonEmptyString},
      {"major", NonNegativeInt},
      {"minor", NonNegativeInt},
      {"patch", NonNegativeInt},
      {"build", NonEmptyString},
      {"platform", NonEmptyString},
      {"platform_like", NonEmptyString},
      {"codename", NormalType},
  };
  validate_rows(data, row_map);
}

// Test for install_date in Windows. This should be removed when other OS get
// this
TEST_F(OsVersion, test_installdate) {
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    SQL results("select install_date from os_version");
    EXPECT_EQ(results.rows().size(), 1U);
    EXPECT_FALSE(results.rows()[0].at("install_date").empty());
  }
}

} // namespace osquery
