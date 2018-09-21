/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
  ValidatatioMap row_map = {{"name", NonEmptyString},
                            {"version", NormalType},
                            {"install_location", NormalType},
                            {"install_source", NormalType},
                            {"language", NormalType},
                            {"publisher", NormalType},
                            {"uninstall_string", NormalType},
                            {"install_date", NormalType},
                            {"identifying_number", NormalType}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
