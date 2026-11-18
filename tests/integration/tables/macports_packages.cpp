/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for macports_packages
// Spec file: specs/darwin/macports_packages.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class macportsPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(macportsPackages, test_sanity) {
  // The table is empty on a host without MacPorts, which is the common case on
  // CI, so only the shape of any returned rows is asserted.
  auto const data = execute_query("select * from macports_packages");
  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"version", NormalType},
      {"revision", NonNegativeInt},
      {"variants", NormalType},
      // MacPorts records this as 0 or 1.
      {"requested", Bool},
      {"arch", NormalType},
      // Install time, stored by MacPorts as a unix timestamp.
      {"date", NonNegativeInt},
      {"prefix", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
