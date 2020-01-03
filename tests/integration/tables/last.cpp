/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for last
// Spec file: specs/posix/last.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class last : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(last, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from last");
  // 2. Check size before validation
  if (data.empty()) {
    LOG(WARNING) << "No entries in wtmp, skipping test";
    return;
  }
  // 3. Build validation map
  ValidationMap row_map = {
      {"username", NormalType},
      {"tty", NormalType},
      {"pid", NonNegativeInt},
      {"type", IntMinMaxCheck(7, 8)},
      {"time", NonNegativeInt},
      {"host", NormalType},
  };
  // 4. Perform validation
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
