
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for arp_cache
// Spec file: specs/arp_cache.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class ArpCacheTest : public IntegrationTableTest {};

TEST_F(ArpCacheTest, test_sanity) {
  QueryData data = execute_query("select * from arp_cache");

  auto const row_map = ValidatatioMap{
      {"address", verifyIpAddress},
      {"mac", verifyMacAddress},
      {"interface", NonEmptyString},
      {"permanent", Bool},
  };
  validate_rows(data, row_map);
}

} // namespace osquery
