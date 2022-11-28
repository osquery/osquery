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

#include <boost/filesystem.hpp>

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
      "select * from mdfind where query = 'kMDItemFSName = \"*.app\"'"
      " LIMIT 10;");

  ASSERT_EQ(rows.size(), 10);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"query", NonEmptyString},
  };
  validate_rows(rows, row_map);

  auto file_path = rows[0]["path"];
  boost::filesystem::path path(file_path);
  auto filename = path.leaf().string();

  rows =
      execute_query("select * from mdfind where query = 'kMDItemFSName = \"" +
                    filename + "\"';");

  ASSERT_FALSE(rows.empty());

  for (auto row : rows) {
    boost::filesystem::path retrieved_path(row["path"]);
    EXPECT_EQ(retrieved_path.leaf().string(), filename);
  }
}

} // namespace table_tests
} // namespace osquery
