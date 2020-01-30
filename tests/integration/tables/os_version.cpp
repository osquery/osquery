/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for os_version
// Spec file: specs/os_version.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

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

  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"version", NonEmptyString},
      {"major", NonNegativeInt},
      {"minor", NonNegativeInt},
      {"patch", NormalType},
      {"build", NormalType},
      {"platform", NonEmptyString},
      {"platform_like", NonEmptyString},
      {"codename", NormalType},
#ifdef OSQUERY_WINDOWS
      {"install_date", NonEmptyString},
#endif
  };

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    row_map["pid_with_namespace"] = IntType;
    row_map["mount_namespace_id"] = NormalType;
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
