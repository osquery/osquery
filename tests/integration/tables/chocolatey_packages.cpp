/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for chocolatey_packages
// Spec file: specs/windows/chocolatey_packages.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ChocolateyPackagesTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ChocolateyPackagesTest, test_sanity) {
  auto const data = execute_query("select * from chocolatey_packages");

  ValidationMap row_map = {
      {"name", NormalType},
      {"version", NormalType},
      {"summary", NormalType},
      {"author", NormalType},
      {"license", NormalType},
      {"path", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
