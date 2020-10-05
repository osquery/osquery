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

class YARATest : public testing::Test {
 protected:
  void SetUp() override {}

  void TearDown() override {}

  Row scanFile(const std::string& ruleContent) {
    YR_RULES* rules = nullptr;
    int result = yr_initialize();
    EXPECT_TRUE(result == ERROR_SUCCESS);

    const auto rule_file = fs::temp_directory_path() /
                           fs::unique_path("osquery.tests.yara.%%%%.%%%%.sig");
    writeTextFile(rule_file.string(), ruleContent);

    Status status = compileSingleFile(rule_file.string(), &rules);
    EXPECT_TRUE(status.ok()) << status.what();

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

    result = yr_rules_scan_file(rules,
                                file_to_scan.string().c_str(),
                                SCAN_FLAGS_FAST_MODE,
                                YARACallback,
                                (void*)&r,
                                0);
    EXPECT_TRUE(result == ERROR_SUCCESS) << " yara error code: " << result;

    yr_rules_destroy(rules);
    fs::remove_all(rule_file);
    fs::remove_all(file_to_scan);
    return r;
  }

  Row scanString(const std::string& rule_defs) {
    YR_RULES* rules = nullptr;
    int result = yr_initialize();
    EXPECT_TRUE(result == ERROR_SUCCESS);

    Status status = compileFromString(rule_defs, &rules);
    EXPECT_TRUE(status.ok()) << status.what();

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

    result = yr_rules_scan_file(rules,
                                file_to_scan.string().c_str(),
                                SCAN_FLAGS_FAST_MODE,
                                YARACallback,
                                (void*)&r,
                                0);
    EXPECT_TRUE(result == ERROR_SUCCESS) << " yara error code: " << result;

    yr_rules_destroy(rules);
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

} // namespace osquery
