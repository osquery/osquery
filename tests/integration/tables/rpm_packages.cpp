/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for rpm_packages
// Spec file: specs/linux/rpm_packages.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class rpmPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(rpmPackages, test_sanity) {
  auto rows = execute_query("select * from rpm_packages");
  if (rows.empty()) {
    LOG(WARNING) << "Empty results of query from 'rpm_packages', assume there "
                    "is no rpm on the system";
    return;
  }

  ValidationMap row_map = {{"name", NonEmptyString},
                           {"version", NormalType},
                           {"release", NormalType},
                           {"source", NormalType},
                           {"size", IntType},
                           {"sha1", NonEmptyString},
                           {"arch", NonEmptyString},
                           {"epoch", IntOrEmpty},
                           {"install_time", IntType},
                           {"vendor", NonEmptyString},
                           {"package_group", NonEmptyString}};

  validate_rows(rows, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    validate_container_rows("rpm_packages", row_map);
  }
}
} // namespace table_tests
} // namespace osquery
