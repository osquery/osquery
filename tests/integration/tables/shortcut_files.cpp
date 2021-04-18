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
class ShortcutFilesTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ShortcutFilesTest, test_sanity) {
  QueryData const rows = execute_query(
      "select * from shortcut_files where path like "
      "'C:\\ProgramData\\Microsoft\\Windows\\Start "
      "Menu\\Programs\\Administrative Tools\\%%'");

  ASSERT_GT(rows.size(), 0ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},        {"target_path", NormalType},
      {"target_modified", NormalType}, {"target_created", NormalType},
      {"target_accessed", NormalType}, {"target_size", NormalType},
      {"relative_path", NormalType},   {"local_path", NormalType},
      {"working_path", NormalType},    {"icon_path", NormalType},
      {"common_path", NormalType},     {"command_args", NormalType},
      {"hostname", NormalType},        {"share_name", NormalType},
      {"device_type", NormalType},     {"volume_serial", NormalType},
      {"mft_entry", NormalType},       {"mft_sequence", NormalType},
      {"description", NormalType},
  };
  validate_rows(rows, row_map);
}
} // namespace table_tests
} // namespace osquery
