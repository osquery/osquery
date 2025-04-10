/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for programs
// Spec file: specs/windows/programs.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ProgramsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ProgramsTest, test_sanity) {
  QueryData data = execute_query("select * from programs");
  ASSERT_GT(data.size(), 0ul);
  ValidationMap row_map = {{"name", NormalType},
                           {"version", NormalType},
                           {"install_location", NormalType},
                           {"install_source", NormalType},
                           {"language", NormalType},
                           {"publisher", NormalType},
                           {"uninstall_string", NormalType},
                           {"install_date", NormalType},
                           {"identifying_number", NormalType},
                           {"package_family_name", NormalType},
                           {"upgrade_code", NormalType}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
