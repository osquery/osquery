/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for nt_info
// Spec file: specs/windows/nt_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class nt_info : public IntegrationTableTest {};

TEST_F(NTdomains, test_sanity) {
  QueryData data = execute_query("select * from nt_info");

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
      {"name", NonEmptyString},
      {"client_site_name", NonEmptyString},
      {"dc_site_name", NonEmptyString},
      {"dns_forest_name", NonEmptyString},
      {"domain_controller_address", NonEmptyString},
      {"domain_controller_name", NonEmptyString},
      {"domain_name", NonEmptyString},
      {"status", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace osquery
