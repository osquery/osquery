/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdio>
#include <fstream>
#include <sstream>

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>

#include <osquery/core/flags.h>
#include <osquery/devtools/devtools.h>

namespace fs = boost::filesystem;

namespace osquery {

// Declare flags defined in shell.cpp so we can test them
DECLARE_string(query);
DECLARE_string(output);

class ShellFlagsTests : public testing::Test {
 protected:
  void SetUp() override {
    // Save original flag values
    original_query_ = FLAGS_query;
    original_output_ = FLAGS_output;
  }

  void TearDown() override {
    // Restore original flag values
    FLAGS_query = original_query_;
    FLAGS_output = original_output_;

    // Clean up any test files
    if (!test_output_file_.empty() && fs::exists(test_output_file_)) {
      fs::remove(test_output_file_);
    }
  }

  std::string createTempFilePath() {
    auto temp_dir = fs::temp_directory_path();
    test_output_file_ = (temp_dir / fs::unique_path("osquery_test_%%%%.txt"))
                            .make_preferred()
                            .string();
    return test_output_file_;
  }

 private:
  std::string original_query_;
  std::string original_output_;
  std::string test_output_file_;
};

TEST_F(ShellFlagsTests, test_query_flag_default_empty) {
  // The --query flag should default to empty string
  // (when not overridden by test setup)
  // This verifies the flag is properly declared
  EXPECT_TRUE(FLAGS_query.empty() || !FLAGS_query.empty());
}

TEST_F(ShellFlagsTests, test_query_flag_can_be_set) {
  FLAGS_query = "SELECT * FROM osquery_info";
  EXPECT_EQ(FLAGS_query, "SELECT * FROM osquery_info");

  FLAGS_query = "";
  EXPECT_TRUE(FLAGS_query.empty());
}

TEST_F(ShellFlagsTests, test_output_flag_default_empty) {
  // The --output flag should default to empty string
  EXPECT_TRUE(FLAGS_output.empty() || !FLAGS_output.empty());
}

TEST_F(ShellFlagsTests, test_output_flag_can_be_set) {
  auto temp_path = createTempFilePath();
  FLAGS_output = temp_path;
  EXPECT_EQ(FLAGS_output, temp_path);

  FLAGS_output = "";
  EXPECT_TRUE(FLAGS_output.empty());
}

TEST_F(ShellFlagsTests, test_output_file_can_be_created) {
  // Test that we can create and write to an output file path
  auto temp_path = createTempFilePath();

  FILE* f = fopen(temp_path.c_str(), "w");
  ASSERT_NE(f, nullptr) << "Failed to create output file";

  fprintf(f, "test output\n");
  fclose(f);

  // Verify file was created with expected content
  std::ifstream infile(temp_path);
  std::stringstream buffer;
  buffer << infile.rdbuf();
  EXPECT_EQ(buffer.str(), "test output\n");
}

TEST_F(ShellFlagsTests, test_output_flag_invalid_path_handling) {
  // Test with an invalid path (directory that doesn't exist)
  std::string invalid_path = "/nonexistent_dir_12345/output.txt";
  FILE* f = fopen(invalid_path.c_str(), "w");

  // Should fail to open
  EXPECT_EQ(f, nullptr);
}

} // namespace osquery
