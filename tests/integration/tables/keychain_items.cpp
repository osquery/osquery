/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
      {"created", NormalType},
      {"modified", NormalType},
      {"type",
       SpecificValuesCheck{"password",
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
