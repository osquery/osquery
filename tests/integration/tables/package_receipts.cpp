/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for package_receipts
// Spec file: specs/darwin/package_receipts.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class packageReceipts : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(packageReceipts, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from package_receipts");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"package_id", NormalType}
  //      {"package_filename", NormalType}
  //      {"version", NormalType}
  //      {"location", NormalType}
  //      {"install_time", NormalType}
  //      {"installer_name", NormalType}
  //      {"path", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

TEST_F(packageReceipts, test_filter_by_package_filename) {
  auto const all =
      execute_query("select package_filename from package_receipts");
  std::string filename;
  for (const auto& row : all) {
    const auto& value = row.at("package_filename");
    if (!value.empty() && value.find('\'') == std::string::npos) {
      filename = value;
      break;
    }
  }
  if (filename.empty()) {
    GTEST_SKIP() << "No package receipts with a package filename";
  }

  // Receipt plists are named after the package identifier, so a match must
  // come from the receipt contents rather than its path.
  auto const data = execute_query(
      "select package_filename from package_receipts where "
      "package_filename = '" +
      filename + "'");
  ASSERT_FALSE(data.empty());
  for (const auto& row : data) {
    EXPECT_EQ(row.at("package_filename"), filename);
  }
}

} // namespace table_tests
} // namespace osquery
