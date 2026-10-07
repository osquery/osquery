/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for snap_packages
// Spec file: specs/linux/snap_packages.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SnapPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SnapPackages, test_sanity) {
  QueryData rows = execute_query("select * from snap_packages");
  if (rows.size() == 0) {
    GTEST_SKIP() << "No snap packages installed on this system";
  }
  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"version", NormalType},
      {"summary", NormalType},
      {"description", NormalType},
      {"type", NonEmptyString},
      {"confinement", NonEmptyString},
      {"base", NormalType},
      {"license", NormalType},
      {"grade", NonEmptyString},
      {"architectures", NormalType},
      {"revision", NonEmptyString},
      {"channel", NormalType},
      {"snap_id", NormalType},
  };

  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
