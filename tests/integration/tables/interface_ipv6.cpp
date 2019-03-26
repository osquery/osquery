/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for interface_ipv6
// Spec file: specs/interface_ipv6.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class InterfaceIpv6Test : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(InterfaceIpv6Test, test_sanity) {
  QueryData const rows = execute_query("select * from interface_ipv6");
  auto const row_map = ValidatatioMap{
      {"interface", NonEmptyString},
      {"hop_limit", IntMinMaxCheck(0, 255)},
      {"forwarding_enabled", Bool},
      {"redirect_accept", Bool},
      {"rtadv_accept", Bool},
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
