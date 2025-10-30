/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for password_policy
// Spec file: specs/darwin/password_policy.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class passwordPolicy : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(passwordPolicy, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from password_policy");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  ValidationMap row_map = {{"uid", IntType},
                           {"policy_identifier", NormalType},
                           {"policy_content", NormalType},
                           {"policy_description", NormalType},
                           {"policy_category", NormalType},
                           {"policy_parameters", NormalType}};
  // 4. Perform validation
  validate_rows(data, row_map);
}

TEST_F(passwordPolicy, test_policy_category_column) {
  // Test that the new policy_category column exists and has expected values
  auto const data =
      execute_query("select policy_category from password_policy");

  // Check that all policy_category values are one of the expected categories
  for (const auto& row : data) {
    auto category = row.at("policy_category");
    EXPECT_TRUE(category == "policyCategoryPasswordContent" ||
                category == "policyCategoryAuthentication" ||
                category == "policyCategoryPasswordChange")
        << "Unexpected policy_category value: " << category;
  }
}

TEST_F(passwordPolicy, test_filter_by_category) {
  // Test filtering by policy category
  auto const password_content_data = execute_query(
      "select * from password_policy where policy_category = "
      "'policyCategoryPasswordContent'");
  auto const auth_data = execute_query(
      "select * from password_policy where policy_category = "
      "'policyCategoryAuthentication'");
  auto const change_data = execute_query(
      "select * from password_policy where policy_category = "
      "'policyCategoryPasswordChange'");

  // All returned rows should have the correct category
  for (const auto& row : password_content_data) {
    EXPECT_EQ(row.at("policy_category"), "policyCategoryPasswordContent");
  }
  for (const auto& row : auth_data) {
    EXPECT_EQ(row.at("policy_category"), "policyCategoryAuthentication");
  }
  for (const auto& row : change_data) {
    EXPECT_EQ(row.at("policy_category"), "policyCategoryPasswordChange");
  }
}

} // namespace table_tests
} // namespace osquery
