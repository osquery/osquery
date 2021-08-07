/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class FsEventsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(FsEventsTest, test_sanity) {
  QueryData const rows = execute_query("select * from fsevents");

  ASSERT_GT(rows.size(), 0ul);

  ValidationMap row_map = {
      {"path", NormalType},
      {"node_id", NormalType},
      {"event_id", NormalType},
      {"flags", NormalType},
      {"source", NormalType},
  };
  validate_rows(rows, row_map);
}
} // namespace table_tests
} // namespace osquery
