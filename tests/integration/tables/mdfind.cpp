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

#include <osquery/logger/logger.h>
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

  // Skip the rest of the assertions if mdfind is disabled. We should still do
  // the first query though just to be sure osquery doesn't crash in that case.
  int mdfind_disabled = system("mdutil -s / | grep disabled");
  if (mdfind_disabled == 0) {
    LOG(INFO) << "Skipping mdfind test because mdfind is disabled";
    GTEST_SKIP() << "mdfind is disabled on this system";
    return;
  }
  const char* github_job = getenv("GITHUB_JOB");
  if (github_job != nullptr && strcmp(github_job, "test_older_macos") == 0) {
    LOG(INFO)
        << "Disabling mdfind test on the older macOS runner due to flakiness";
    GTEST_SKIP() << "mdfind test disabled on older macOS runner";
    return;
  }

  ASSERT_EQ(rows.size(), 10);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"query", NonEmptyString},
  };
  validate_rows(rows, row_map);

  auto file_path = rows[0]["path"];
  boost::filesystem::path path(file_path);
  auto filename = path.filename().string();

  rows =
      execute_query("select * from mdfind where query = 'kMDItemFSName = \"" +
                    filename + "\"';");

  ASSERT_FALSE(rows.empty());

  for (auto row : rows) {
    boost::filesystem::path retrieved_path(row["path"]);
    EXPECT_EQ(retrieved_path.filename().string(), filename);
  }
}

} // namespace table_tests
} // namespace osquery
