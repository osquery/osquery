/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class Secureboot : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(Secureboot, test_sanity) {
  QueryData data = execute_query("select * from secureboot");

  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"secure_boot", IntOrEmpty},
      {"setup_mode", IntOrEmpty},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
