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
namespace table_tests {

class OsVersion : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(OsVersion, test_sanity) {
  QueryData data = execute_query("select * from os_version");

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
      {"name", NonEmptyString},
      {"version", NonEmptyString},
      {"major", NonNegativeInt},
      {"minor", NonNegativeInt},
      {"patch", NonNegativeInt},
      {"build", NormalType},
      {"platform", NonEmptyString},
      {"platform_like", NonEmptyString},
      {"codename", NormalType},
#ifdef OSQUERY_WINDOWS
      {"installdate", NonEmptyString},
#endif
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
