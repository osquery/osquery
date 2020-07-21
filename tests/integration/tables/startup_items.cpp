/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for startup_items
// Spec file: specs/macwin/startup_items.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class StartupItemsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(StartupItemsTest, test_sanity) {
  auto const data = execute_query("select * from startup_items");

  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"path", NonEmptyString},
      {"args", NormalType},
      {"type", SpecificValuesCheck{"Startup Item", "Login Item"}},
      {"source", NonEmptyString},
      {"status", SpecificValuesCheck{"enabled", "disabled"}},
      {"username", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
