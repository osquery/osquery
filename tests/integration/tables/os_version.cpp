/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
      {"arch", NonEmptyString},
#ifdef OSQUERY_WINDOWS
      {"install_date", NonEmptyString},
#endif
  };

  validate_rows(data, row_map);

  // Query again with hidden columns too
  if (isPlatform(PlatformType::TYPE_LINUX)) {
    validate_container_rows("os_version", row_map);
  }
}

} // namespace table_tests
} // namespace osquery
