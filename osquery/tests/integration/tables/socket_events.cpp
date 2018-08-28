
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for socket_events
// Spec file: specs/linux/socket_events.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class socketEvents : public IntegrationTableTest {};

TEST_F(socketEvents, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from socket_events");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"action", NormalType}
  //      {"pid", IntType}
  //      {"path", NormalType}
  //      {"fd", NormalType}
  //      {"auid", IntType}
  //      {"success", IntType}
  //      {"family", IntType}
  //      {"protocol", IntType}
  //      {"local_address", NormalType}
  //      {"remote_address", NormalType}
  //      {"local_port", IntType}
  //      {"remote_port", IntType}
  //      {"socket", NormalType}
  //      {"time", IntType}
  //      {"uptime", IntType}
  //      {"eid", NormalType}
  //}
  // 4. Perform validation
  // EXPECT_TRUE(validate_rows(data, row_map));
}

} // namespace osquery
