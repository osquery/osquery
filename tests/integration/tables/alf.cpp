/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for alf
// Spec file: specs/darwin/alf.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class alf : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(alf, test_sanity) {
  auto const data = execute_query("select * from alf");
  ASSERT_EQ(data.size(), 1ul);

  const auto& qd = SQL::selectAllFrom("os_version");
  ASSERT_EQ(qd.size(), 1ul);

  const auto macOS15Plus = qd.front().at("major") >= "15";

  ValidationMap row_map = {
      {"global_state", IntType},
      {"logging_enabled", IntType},
      {"stealth_enabled", IntType},
      {"version", NormalType},
  };

  if (macOS15Plus) {
    // The following fields are empty for macOS 15+.
    row_map["allow_signed_enabled"] = EmptyOk;
    row_map["firewall_unload"] = EmptyOk;
    row_map["logging_option"] = EmptyOk;
  } else {
    row_map["allow_signed_enabled"] = IntType;
    row_map["firewall_unload"] = IntType;
    row_map["logging_option"] = IntType;
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
