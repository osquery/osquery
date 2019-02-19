
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for windows_crashes
// Spec file: specs/windows/windows_crashes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class windowsCrashes : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(windowsCrashes, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from windows_crashes");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"datetime", NormalType}
  //      {"module", NormalType}
  //      {"path", NormalType}
  //      {"pid", IntType}
  //      {"tid", IntType}
  //      {"version", NormalType}
  //      {"process_uptime", IntType}
  //      {"stack_trace", NormalType}
  //      {"exception_code", NormalType}
  //      {"exception_message", NormalType}
  //      {"exception_address", NormalType}
  //      {"registers", NormalType}
  //      {"command_line", NormalType}
  //      {"current_directory", NormalType}
  //      {"username", NormalType}
  //      {"machine_name", NormalType}
  //      {"major_version", IntType}
  //      {"minor_version", IntType}
  //      {"build_number", IntType}
  //      {"type", NormalType}
  //      {"crash_path", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
