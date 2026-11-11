/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class SshdConfig : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SshdConfig, test_sanity) {
  struct TestCase {
    std::string query;
    size_t wantNumRows;
    ValidationMap row_map;
  };

  TestCase testCases[] = {{
      // return 0 rows if unable to read file.
      "select * from sshd_config where path='/foo/bar/baz';",
      0,
      {},
  }};

  for (TestCase tc : testCases) {
    QueryData data = execute_query(tc.query);

    ASSERT_EQ(data.size(), tc.wantNumRows);

    validate_rows(data, tc.row_map);
  }
}

} // namespace table_tests
} // namespace osquery
