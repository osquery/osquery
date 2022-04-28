/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for keychain_items
// Spec file: specs/darwin/keychain_items.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class KeychainItemsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(KeychainItemsTest, test_sanity) {
  ValidationMap row_map = {
      {"label", NormalType},
      {"description", NormalType},
      {"comment", NormalType},
      {"account", NormalType},
      {"created", NormalType},
      {"modified", NormalType},
      {"type",
       SpecificValuesCheck{"password",
                           "internet password",
                           "certificate",
                           "symmetric key",
                           "public key",
                           "private key"}},
      {"path", NonEmptyString},
  };

  auto const data = execute_query("select * from keychain_items");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
