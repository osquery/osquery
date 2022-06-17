/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/yara/yara_utils.h>

#include <boost/filesystem.hpp>

#include <fstream>

namespace fs = boost::filesystem;

namespace osquery {

const std::string alwaysTrue = "rule always_true { condition: true }";
const std::string alwaysFalse = "rule always_false { condition: false }";
const std::string invalidRule = "rule invalid { Not a valid rule }";

class YARATest : public testing::Test {
 protected:
  void SetUp() override {}

  void TearDown() override {
    yr_finalize();
  }

  Row scanFile(const std::string& ruleContent) {
    int result = yr_initialize();
    bool init_succeeded = result == ERROR_SUCCESS;
    EXPECT_TRUE(init_succeeded);

    if (!init_succeeded) {
      return {};
    }

    const auto rule_file = fs::temp_directory_path() /
                           fs::unique_path("osquery.tests.yara.%%%%.%%%%.sig");
    writeTextFile(rule_file.string(), ruleContent);

    auto compiler_result = compileSingleFile(rule_file.string());
    EXPECT_TRUE(compiler_result.isValue())
        << compiler_result.getError().getMessage();

    if (compiler_result.isError()) {
      return {};
    }

    Row r;
    r["count"] = "0";
    r["matches"] = "";

    const auto file_to_scan =
        fs::temp_directory_path() /
        fs::unique_path("osquery.tests.yara.%%%%.%%%%.bin");
    {
      std::ofstream test_file(file_to_scan.string());
      test_file << "test\n";
    }

    auto rules_handle = compiler_result.take();

    result = yr_rules_scan_file(rules_handle.get(),
                                file_to_scan.string().c_str(),
                                SCAN_FLAGS_FAST_MODE,
                                YARACallback,
                                (void*)&r,
                                0);
    EXPECT_TRUE(result == ERROR_SUCCESS) << " yara error code: " << result;

    fs::remove_all(rule_file);
    fs::remove_all(file_to_scan);
    return r;
  }

  Row scanString(const std::string& rule_defs) {
    int result = yr_initialize();
    bool init_succeeded = result == ERROR_SUCCESS;
    EXPECT_TRUE(init_succeeded);

    if (!init_succeeded) {
      return {};
    }

    auto compiler_result = compileFromString(rule_defs);
    EXPECT_TRUE(compiler_result.isValue())
        << compiler_result.getError().getMessage();

    if (compiler_result.isError()) {
      return {};
    }

    Row r;
    r["count"] = "0";
    r["matches"] = "";

    const auto file_to_scan =
        fs::temp_directory_path() /
        fs::unique_path("osquery.tests.yara.%%%%.%%%%.bin");
    {
      std::ofstream test_file(file_to_scan.string());
      test_file << "test\n";
    }

    auto rules_handle = compiler_result.take();
    result = yr_rules_scan_file(rules_handle.get(),
                                file_to_scan.string().c_str(),
                                SCAN_FLAGS_FAST_MODE,
                                YARACallback,
                                (void*)&r,
                                0);
    EXPECT_TRUE(result == ERROR_SUCCESS) << " yara error code: " << result;

    fs::remove_all(file_to_scan);
    return r;
  }
};

TEST_F(YARATest, test_match_true) {
  Row r = scanFile(alwaysTrue);
  // Should have 1 count
  EXPECT_TRUE(r["count"] == "1");
}

TEST_F(YARATest, test_match_false) {
  Row r = scanFile(alwaysFalse);
  // Should have 0 count
  EXPECT_TRUE(r["count"] == "0");
}

TEST_F(YARATest, should_skip_file) {
  // pretty much any regular file should be scanned

  EXPECT_FALSE(yaraShouldSkipFile("/any/file/here", S_IFREG));

  // should skip devices, pipes, sockets, directories, etc.

  EXPECT_TRUE(yaraShouldSkipFile("/any/file/here", S_IFCHR));
  EXPECT_TRUE(yaraShouldSkipFile("/any/file/here", S_IFDIR));
#ifdef __APPLE__
  EXPECT_TRUE(yaraShouldSkipFile("/any/file/here", S_IFLNK));
  EXPECT_TRUE(yaraShouldSkipFile("/any/file/here", S_IFSOCK));
  EXPECT_TRUE(yaraShouldSkipFile("/any/file/here", S_IFBLK));
  EXPECT_TRUE(yaraShouldSkipFile("/any/file/here", S_IFIFO));
#endif
}

TEST_F(YARATest, test_match_string_true) {
  Row r = scanString(alwaysTrue);
  // expect count 1
  EXPECT_TRUE(r["count"] == "1");
}

TEST_F(YARATest, test_match_string_false) {
  Row r = scanString(alwaysFalse);
  // expect count 0
  EXPECT_TRUE(r["count"] == "0");
}

TEST_F(YARATest, test_rule_compilation_failures) {
  int result = yr_initialize();
  EXPECT_TRUE(result == ERROR_SUCCESS);

  /* This comes from a regression where Yara internal functions
     like strlcpy are incorrectly called, causing a segfault;
     strlcpy is used to copy the error message. */
  auto compiler_result = compileSingleFile(fs::temp_directory_path().string());
  EXPECT_TRUE(compiler_result.isError())
      << compiler_result.getError().getMessage();

  /* Same as above, but this will cause a crash also on Windows
     (due to the syntax error), if there are issues with those functions. */
  compiler_result = compileFromString(invalidRule);
  EXPECT_TRUE(compiler_result.isError());

  // Simple test to verify that the API handles non existing files cleanly
  compiler_result = compileSingleFile("/tmp/this_path_doesnt_exists");
  EXPECT_TRUE(compiler_result.isError());
}

} // namespace osquery
