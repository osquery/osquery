/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for crashes
// Spec file: specs/darwin/crashes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class crashes : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(crashes, test_sanity) {
  ValidationMap row_map = {
      {"type", NormalType},
      {"pid", IntType},
      {"path", NormalType},
      {"crash_path", NormalType},
      {"identifier", NormalType},
      {"version", NormalType},
      {"parent", IntType},
      {"responsible", NormalType},
      {"uid", IntType},
      {"datetime", NormalType},
      {"crashed_thread", IntType},
      {"stack_trace", NormalType},
      {"exception_type", NormalType},
      {"exception_codes", NormalType},
      {"exception_notes", NormalType},
      {"registers", NormalType},
  };

  auto const data = execute_query(
      "select crashes.* from users CROSS JOIN crashes "
      "USING(uid)");
  if (!data.empty()) {
    // Lets not assume there are crashes on the host.
    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery
