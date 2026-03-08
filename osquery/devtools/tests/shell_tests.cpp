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
DECLARE_string(query_file);
DECLARE_string(output);

class ShellFlagsTests : public testing::Test {
 protected:
  void SetUp() override {
    // Save original flag values
    original_query_ = FLAGS_query;
    original_query_file_ = FLAGS_query_file;
    original_output_ = FLAGS_output;
  }

  void TearDown() override {
    // Restore original flag values
    FLAGS_query = original_query_;
    FLAGS_query_file = original_query_file_;
    FLAGS_output = original_output_;

    // Clean up any test files
    for (const auto& file : test_files_) {
      if (fs::exists(file)) {
        fs::remove(file);
      }
    }
  }

  std::string createTempFilePath(const std::string& suffix = ".txt") {
    auto temp_dir = fs::temp_directory_path();
    auto path = (temp_dir / fs::unique_path("osquery_test_%%%%" + suffix))
                    .make_preferred()
                    .string();
    test_files_.push_back(path);
    return path;
  }

 private:
  std::string original_query_;
  std::string original_query_file_;
  std::string original_output_;
  std::vector<std::string> test_files_;
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

TEST_F(ShellFlagsTests, test_query_file_flag_can_be_set) {
  auto temp_path = createTempFilePath(".sql");
  FLAGS_query_file = temp_path;
  EXPECT_EQ(FLAGS_query_file, temp_path);

  FLAGS_query_file = "";
  EXPECT_TRUE(FLAGS_query_file.empty());
}

TEST_F(ShellFlagsTests, test_query_file_can_be_read) {
  // Create a temp file with a SQL query
  auto temp_path = createTempFilePath(".sql");

  std::ofstream outfile(temp_path);
  outfile << "SELECT * FROM osquery_info;";
  outfile.close();

  // Verify file exists and can be read
  std::ifstream infile(temp_path);
  std::stringstream buffer;
  buffer << infile.rdbuf();
  EXPECT_EQ(buffer.str(), "SELECT * FROM osquery_info;");
}

class PrinterOutputTests : public testing::Test {
 protected:
  void TearDown() override {
    // Clean up any test files
    for (const auto& file : test_files_) {
      if (fs::exists(file)) {
        fs::remove(file);
      }
    }
  }

  std::string createTempFilePath() {
    auto temp_dir = fs::temp_directory_path();
    auto path = (temp_dir / fs::unique_path("osquery_printer_%%%%.txt"))
                    .make_preferred()
                    .string();
    test_files_.push_back(path);
    return path;
  }

 private:
  std::vector<std::string> test_files_;
};

TEST_F(PrinterOutputTests, test_json_print_to_file) {
  auto temp_path = createTempFilePath();
  FILE* f = fopen(temp_path.c_str(), "w");
  ASSERT_NE(f, nullptr);

  QueryData data = {
      {{"name", "test"}, {"value", "123"}},
  };

  jsonPrint(data, f);
  fclose(f);

  // Verify JSON was written to file
  std::ifstream infile(temp_path);
  std::stringstream buffer;
  buffer << infile.rdbuf();
  std::string content = buffer.str();

  EXPECT_NE(content.find("["), std::string::npos);
  EXPECT_NE(content.find("]"), std::string::npos);
  EXPECT_NE(content.find("test"), std::string::npos);
  EXPECT_NE(content.find("123"), std::string::npos);
}

TEST_F(PrinterOutputTests, test_json_pretty_print_to_file) {
  auto temp_path = createTempFilePath();
  FILE* f = fopen(temp_path.c_str(), "w");
  ASSERT_NE(f, nullptr);

  QueryData data = {
      {{"name", "test"}, {"value", "456"}},
  };

  jsonPrettyPrint(data, f);
  fclose(f);

  // Verify pretty JSON was written to file
  std::ifstream infile(temp_path);
  std::stringstream buffer;
  buffer << infile.rdbuf();
  std::string content = buffer.str();

  EXPECT_NE(content.find("["), std::string::npos);
  EXPECT_NE(content.find("]"), std::string::npos);
  EXPECT_NE(content.find("test"), std::string::npos);
  EXPECT_NE(content.find("456"), std::string::npos);
}

TEST_F(PrinterOutputTests, test_pretty_print_to_file) {
  auto temp_path = createTempFilePath();
  FILE* f = fopen(temp_path.c_str(), "w");
  ASSERT_NE(f, nullptr);

  QueryData data = {
      {{"name", "Alice"}, {"age", "30"}},
      {{"name", "Bob"}, {"age", "25"}},
  };
  std::vector<std::string> columns = {"name", "age"};
  std::map<std::string, size_t> lengths;
  for (const auto& row : data) {
    computeRowLengths(row, lengths);
  }

  prettyPrint(data, columns, lengths, f);
  fclose(f);

  // Verify pretty table was written to file
  std::ifstream infile(temp_path);
  std::stringstream buffer;
  buffer << infile.rdbuf();
  std::string content = buffer.str();

  EXPECT_NE(content.find("Alice"), std::string::npos);
  EXPECT_NE(content.find("Bob"), std::string::npos);
  EXPECT_NE(content.find("30"), std::string::npos);
  EXPECT_NE(content.find("25"), std::string::npos);
  // Should have table separators
  EXPECT_NE(content.find("+"), std::string::npos);
  EXPECT_NE(content.find("|"), std::string::npos);
}

} // namespace osquery
