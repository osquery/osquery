/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for flatpak_packages
// Spec file: specs/linux/flatpak_packages.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class FlatpakPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(FlatpakPackages, test_sanity) {
  QueryData rows = execute_query("select * from flatpak_packages");
  if (rows.size() == 0) {
    GTEST_SKIP() << "No Flatpak packages installed on this system";
  }

  ValidationMap row_map = {
      {"name", NormalType},
      {"app_id", NonEmptyString},
      {"version", NormalType},
      {"arch", NormalType},
      {"branch", NormalType},
      {"commit", NormalType},
      {"origin", NormalType},
      {"runtime", NormalType},
      {"type", NormalType},
      {"installation", NonEmptyString},
      {"summary", NormalType},
      {"description", NormalType},
      {"license", NormalType},
      {"homepage", NormalType},
      {"developer_name", NormalType},
  };

  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
