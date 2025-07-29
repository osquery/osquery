/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for deb_package_files
// Spec file: specs/linux/deb_package_files.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class DebPackageFiles : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(DebPackageFiles, test_sanity) {
  auto rows = execute_query("select * from deb_package_files");
  if (!rows.empty()) {
    ValidationMap row_map = {
        {"package", NonEmptyString},
        {"path", NonEmptyString},
        {"admindir", NonEmptyString},
    };
    validate_rows(rows, row_map);
  } else {
    LOG(WARNING) << "Empty results of query from 'deb_package_files', assume "
                    "there are no DEB packages installed on the system";
  }
}

} // namespace table_tests
} // namespace osquery
