/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for alf_explicit_auths
// Spec file: specs/darwin/alf_explicit_auths.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class alfExplicitAuths : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(alfExplicitAuths, test_sanity) {
  auto const data = execute_query("select * from alf_explicit_auths");

  const auto& qd = SQL::selectAllFrom("os_version");
  ASSERT_EQ(qd.size(), 1ul);

  const auto macOS15Plus = qd.front().at("major") >= "15";

  if (macOS15Plus) {
    ASSERT_EQ(data.size(), 0ul);
    return;
  }

  ValidationMap row_map = {
      {"process", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
