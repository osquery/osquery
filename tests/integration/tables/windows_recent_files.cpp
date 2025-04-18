/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for windows_recent_files
// Spec file: specs/windows/windows_recent_files.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class WindowsRecentFilesTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(WindowsRecentFilesTest, test_sanity) {
  auto const data = execute_query("select * from windows_recent_files");

  EXPECT_GT(data.size(), 0ul);

  ValidationMap row_map = {
      {"filename", NormalType},
      {"path", NonEmptyString},
      {"mtime", NonNegativeInt},
      {"type", NonEmptyString},
      {"shortcut_path", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
