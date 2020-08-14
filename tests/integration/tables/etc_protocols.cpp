/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for etc_protocols
// Spec file: specs/etc_protocols.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class EtcProtocolsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(EtcProtocolsTest, test_sanity) {
  auto const rows = execute_query("select * from etc_protocols");
  auto const row_map = ValidationMap{
      {"name", NonEmptyString},
      {"number", NonNegativeInt},
      {"alias", NonNull},
      {"comment", NormalType},
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
