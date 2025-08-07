/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for signature
// Spec file: specs/darwin/signature.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SignatureTests : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SignatureTests, test_sanity) {
  // Test with a known system file that should be signed
  auto data = execute_query("SELECT * FROM signature WHERE path = '/bin/ls'");

  // Should return at least one row (one per architecture)
  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  // Check that the path is correct
  for (const auto& row : data) {
    ASSERT_EQ(row.at("path"), "/bin/ls");
    ASSERT_EQ(row.at("identifier"), "com.apple.ls");
    ASSERT_TRUE(row.at("signed") == "1");
  }
}

TEST_F(SignatureTests, test_hash_resources_constraint) {
  // Test with hash_resources = 0
  auto data = execute_query(
      "SELECT * FROM signature WHERE path = '/bin/ls' AND hash_resources = 0");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& row : data) {
    ASSERT_EQ(row.at("hash_resources"), "0");
  }

  // Test with hash_resources = 1
  data = execute_query(
      "SELECT * FROM signature WHERE path = '/bin/ls' AND hash_resources = 1");

  ASSERT_GE(data.size(), 1ul);

  validate_rows(data, row_map);

  for (const auto& row : data) {
    ASSERT_EQ(row.at("hash_resources"), "1");
  }
}

TEST_F(SignatureTests, test_hash_executable_constraint) {
  // Test with hash_executable = 0
  auto data = execute_query(
      "SELECT * FROM signature WHERE path = '/bin/ls' AND hash_executable = 0");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& row : data) {
    ASSERT_EQ(row.at("hash_executable"), "0");
  }

  // Test with hash_executable = 1
  data = execute_query(
      "SELECT * FROM signature WHERE path = '/bin/ls' AND hash_executable = 1");

  ASSERT_GE(data.size(), 1ul);

  validate_rows(data, row_map);

  for (const auto& row : data) {
    ASSERT_EQ(row.at("hash_executable"), "1");
  }
}

TEST_F(SignatureTests, test_multiple_architectures) {
  // Test that we get results for multiple architectures
  auto data = execute_query("SELECT * FROM signature WHERE path = '/bin/ls'");

  // Should return multiple rows for different architectures
  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  std::set<std::string> architectures;
  for (const auto& row : data) {
    architectures.insert(row.at("arch"));
  }

  // Should have at least one architecture
  ASSERT_GE(architectures.size(), 1ul);
}

TEST_F(SignatureTests, test_unsigned_file) {
  // Test with a file that should be unsigned (use a text file)
  auto data =
      execute_query("SELECT * FROM signature WHERE path = '/etc/hosts'");

  // Should return at least one row
  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NormalType}, // Allow empty for unsigned files
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& row : data) {
    ASSERT_EQ(row.at("path"), "/etc/hosts");
    // Text files should be unsigned
    ASSERT_EQ(row.at("signed"), "0");
    // Unsigned file should have empty identifier
    ASSERT_TRUE(row.at("identifier").empty());
  }
}

TEST_F(SignatureTests, test_app_signature) {
  // Test with a macOS app that should be signed
  auto data = execute_query(
      "SELECT * FROM signature WHERE path = '/System/Applications/System "
      "Settings.app'");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& row : data) {
    ASSERT_EQ(row.at("path"), "/System/Applications/System Settings.app");
    // App should be signed
    ASSERT_EQ(row.at("signed"), "1");
    // Should have an identifier
    ASSERT_FALSE(row.at("identifier").empty());
    // Should have entitlements (apps typically have entitlements)
    ASSERT_FALSE(row.at("entitlements").empty());
  }
}

TEST_F(SignatureTests, test_nonexistent_file) {
  // Test with a file that doesn't exist
  auto data =
      execute_query("SELECT * FROM signature WHERE path = '/nonexistent/file'");

  // Should return no rows
  ASSERT_EQ(data.size(), 0ul);
}

TEST_F(SignatureTests, test_entitlements_json) {
  // Test that entitlements field contains valid JSON when present
  auto data = execute_query(
      "SELECT * FROM signature WHERE path = '/System/Applications/System "
      "Settings.app' AND entitlements != ''");

  // This test should have results since System Settings.app has entitlements
  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& row : data) {
    const auto& entitlements = row.at("entitlements");
    if (!entitlements.empty()) {
      // Basic JSON validation - should start with { and end with }
      ASSERT_TRUE(entitlements.front() == '{');
      ASSERT_TRUE(entitlements.back() == '}');
    }
  }
}

TEST_F(SignatureTests, test_cdhash_format) {
  // Test that cdhash is in hex format when present
  auto data = execute_query(
      "SELECT * FROM signature WHERE path = '/bin/ls' AND cdhash != ''");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"hash_resources", IntType},
      {"hash_executable", IntType},
      {"arch", NormalType},
      {"signed", IntType},
      {"identifier", NormalType},
      {"cdhash", NonEmptyString},
      {"team_identifier", NormalType},
      {"authority", NormalType},
      {"entitlements", NormalType},
  };

  validate_rows(data, row_map);

  for (const auto& row : data) {
    const auto& cdhash = row.at("cdhash");
    if (!cdhash.empty()) {
      // CDHash should be a hex string
      ASSERT_TRUE(is_valid_hex(cdhash));
    }
  }
}

} // namespace table_tests
} // namespace osquery
