/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
