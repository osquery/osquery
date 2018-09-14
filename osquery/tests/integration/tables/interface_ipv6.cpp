/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for interface_ipv6
// Spec file: specs/interface_ipv6.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class InterfaceIpv6Test : public IntegrationTableTest {};

TEST_F(InterfaceIpv6Test, sanity) {
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

} // namespace osquery
