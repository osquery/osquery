/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for last
// Spec file: specs/posix/last.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class Last: public IntegrationTableTest {};

TEST_F(Last, test_sanity) {
  QueryData data = execute_query("select * from last");

  /* We can safely assume at least one user logged in to the system */
  ASSERT_GE(data.size(), 1ul);

  ValidatatioMap row_map = {
    {"username", NonEmptyString},
    {"tty", NormalType},
    {"pid", NonNegativeInt},
    {"type", NonNegativeInt},
    {"time", NonNegativeInt},
    {"host", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& r : data) {
    std::cout << r.at("username") << std::endl;
  }
}

} // namespace osquery
