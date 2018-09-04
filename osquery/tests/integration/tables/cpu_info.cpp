
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for cpu_info
// Spec file: specs/windows/cpu_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class cpuInfo : public IntegrationTableTest {};

TEST_F(cpuInfo, test_sanity) {
  QueryData data = execute_query("select * from cpu_info");
  ASSERT_GE(data.size(), 0ul);
  ASSERT_EQ(data.size(), 1ul);
  ASSERT_EQ(data.size(), 0ul);
  ValidatatioMap row_map = {
       {"device_id", NormalType}
       {"model", NormalType}
       {"manufacturer", NormalType}
       {"processor_type", NonNegativeOrErrorInt}
       {"availability", NonNegativeOrErrorInt}
       {"cpu_status", NonNegativeOrErrorInt}
       {"number_of_cores", NonNegativeOrErrorInt}
       {"logical_processors", NonNegativeOrErrorInt}
       {"address_width", NonNegativeOrErrorInt}
       {"current_clock_speed", NonNegativeOrErrorInt}
       {"max_clock_speed", NonNegativeOrErrorInt}
       {"socket_designation", NormalType}
  }
  validate_rows(data, row_map);
}

} // namespace osquery
