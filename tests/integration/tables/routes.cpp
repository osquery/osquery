
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for routes
// Spec file: specs/routes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class RoutesTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(RoutesTest, test_sanity) {
  QueryData const data = execute_query("select * from routes");

  auto const row_map = ValidatatioMap{
      {"destination", verifyIpAddress},
      {"netmask", IntMinMaxCheck(0, 128)},
      {"gateway", NormalType},
      {"source", verifyEmptyStringOrIpAddress},
      {"flags", IntType},
      {"interface", NormalType},
      {"mtu", IntType},
      {"metric", IntType},
      {"type",
       SpecificValuesCheck{
           "anycast",
           "broadcast",
           "dynamic",
           "gateway",
           "local",
           "other",
           "remote",
           "router",
           "static",
       }},
#ifdef OSQUERY_POSIX
      {"hopcount", IntMinMaxCheck(0, 255)},
#endif
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
