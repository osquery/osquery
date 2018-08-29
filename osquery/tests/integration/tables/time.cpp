/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for time
// Spec file: specs/utility/time.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class Time : public IntegrationTableTest {};

TEST_F(Time, test_sanity) {
  QueryData data = execute_query("select * from time");

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
       {"weekday", NonEmptyString},
       {"year", IntType},
       {"month", IntType},
       {"day", IntType},
       {"hour", IntType},
       {"minutes", IntType},
       {"seconds", IntType},
       {"timezone", NonEmptyString},
       {"local_time", IntType},
       {"local_timezone", NonEmptyString},
       {"unix_time", IntType},
       {"timestamp", NonEmptyString},
       {"datetime", NonEmptyString},
       {"iso_8601", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace osquery
