/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for npm_packages
// Spec file: specs/linux/npm_packages.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class NpmPackagesTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(NpmPackagesTest, test_sanity) {
  auto data = execute_query("select * from npm_packages");

  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"version", NonEmptyString},
      {"description", NormalType},
      {"homepage", NormalType},
      {"author", NormalType},
      {"license", NormalType},
      {"path", NonEmptyString},
      {"directory", NonEmptyString},
  };

  validate_rows(data, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    validate_container_rows("npm_packages", row_map);
  }
}

} // namespace table_tests
} // namespace osquery
