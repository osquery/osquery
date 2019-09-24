/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for windows_security_products
// Spec file: specs/windows/windows_security_products.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class WindowsSecurityProductsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(WindowsSecurityProductsTest, test_sanity) {
  auto const data = execute_query("select * from windows_security_products");

  ValidatatioMap row_map = {
      {"type", SpecificValuesCheck{"Firewall", "Antivirus", "Antispyware"}},
      {"name", NonEmptyString},
      {"state", SpecificValuesCheck{"On", "Off", "Snoozed", "Expired"}},
      {"state_timestamp", NormalType},
      {"remediation_path", NormalType},
      {"signatures_up_to_date", Bool},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
