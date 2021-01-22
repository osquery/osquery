/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for system_info
// Spec file: specs/system_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SystemExtension : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SystemExtension, test_sanity) {
  QueryData data = execute_query("select * from system_extensions");
  ValidationMap row_map = {{"path", NormalType},
                           {"UUID", NormalType},
                           {"state", NormalType},
                           {"identifier", NormalType},
                           {"version", NormalType},
                           {"category", NormalType},
                           {"bundle_path", NormalType},
                           {"team", NormalType},
                           {"mdm_managed", NonNegativeInt}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
