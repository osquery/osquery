/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class connectedDisplays : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(connectedDisplays, test_sanity) {
  auto const data = execute_query("select * from connected_displays");
  ValidationMap row_map = {
      {"name", NormalType},
      {"product_id", NormalType},
      {"serial_number", NormalType},
      {"vendor_id", NormalType},
      {"manufactured_week", IntType},
      {"manufactured_year", IntType},
      {"display_id", NormalType},
      {"pixels", NormalType},
      {"resolution", NormalType},
      {"ambient_brightness_enabled", IntType},
      {"connection_type", NormalType},
      {"display_type", NormalType},
      {"main", IntType},
      {"mirror", IntType},
      {"online", IntType},
      {"rotation", IntType},

  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
