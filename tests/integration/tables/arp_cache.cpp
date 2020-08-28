/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for arp_cache
// Spec file: specs/arp_cache.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ArpCacheTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(ArpCacheTest, test_sanity) {
  QueryData data = execute_query("select * from arp_cache");

  auto const row_map = ValidationMap{
      {"address", verifyIpAddress},
      {"mac", verifyMacAddress},
      {"interface", NonEmptyString},
      {"permanent", Bool},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
