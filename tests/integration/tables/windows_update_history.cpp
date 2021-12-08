/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for connectivity
// Spec file: specs/windows/windows_firewall_rules.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class windows_update_history : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(windows_update_history, test_sanity) {
  auto const data =
      execute_query("select * from windows_update_history LIMIT 1");

  // The build box might not have any history of updates
  if (data.size() > 0) {
    ASSERT_EQ(data.size(), 1ul);

    ValidationMap row_map = {
        {"client_app_id", NormalType},
        {"date", IntType},
        {"description", NormalType},
        {"hresult", IntType},
        {"operation", NormalType},
        {"result_code", NormalType},
        {"server_selection", NormalType},
        {"service_id", NormalType},
        {"support_url", NormalType},
        {"title", NormalType},
        {"update_id", NormalType},
        {"update_revision", IntType},
    };

    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery
