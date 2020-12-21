/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for location_services
// Spec file: specs/darwin/location_services.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class locationServices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(locationServices, test_sanity) {
  auto const data = execute_query("select * from location_services");
  ASSERT_EQ(data.size(), 1ul);
  ValidationMap row_map = {
      {"enabled", IntType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
