/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for patches
// Spec file: specs/windows/patches.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class patches : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(patches, test_sanity) {
  auto const data = execute_query("select * from patches");

  // The system might not have any patches installed
  if (data.size() > 0) {
    ValidationMap row_map = {
        {"csname", NormalType},
        {"hotfix_id", NormalType},
        {"caption", NormalType},
        {"description", NormalType},
        {"fix_comments", NormalType},
        {"installed_by", NormalType},
        // install_date is deprecated/hidden, not included in SELECT *
        {"installed_on", NormalType},
        // installed_on_unix is a unix timestamp parsed from installed_on
        {"installed_on_unix", IntOrEmpty},
    };

    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery
