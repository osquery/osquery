
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for socket_events
// Spec file: specs/linux/socket_events.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class socketEvents : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(socketEvents, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from socket_events");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
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
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
