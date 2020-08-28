/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for mdfind
// Spec file: specs/darwin/mdfind.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class Mdfind : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(Mdfind, test_sanity) {
  QueryData rows = execute_query(
      "select * from mdfind where query = 'kMDItemFSName = \"hosts.equiv\"';");
  if (rows.empty()) {
    // Spotlight may be disabled.
    QueryData sl_check = execute_query(
        "select pid from processes where path = "
        "'/System/Library/CoreServices/Spotlight.app/Contents/MacOS/"
        "Spotlight'");
    ASSERT_TRUE(sl_check.empty());
  }

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"query", NonEmptyString},
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
