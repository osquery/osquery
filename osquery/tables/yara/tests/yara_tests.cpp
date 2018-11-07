/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/tables/yara/yara_utils.h"

namespace fs = boost::filesystem;

namespace osquery {
#ifdef WIN32
const std::string ruleFile = "osquery-test-yara.sig";
#else
const std::string ruleFile = "/tmp/osquery-yara.sig";
#endif
const std::string alwaysTrue = "rule always_true { condition: true }";
const std::string alwaysFalse = "rule always_false { condition: false }";

const std::string ruleShouldMatch = "rule myrule {\n"
" meta:\n"
"  description=\"Some details here\"\n"
" strings:\n"
"  $s1 = \"lorem ipsum\" fullword ascii\n"
"  $s2 = \"some.example.org\" ascii\n"
" condition:\n"
"  ( uint16(0) == 0x0a0d and filesize < 600KB ) and all of ($s*)\n"
"}";

const std::string FILE_START = "\r\nx7 lorem ipsum";
const std::string FILE_PART = "\n some stuff ou812 some.example.org\t ";

static std::string testTargetFile = "";
static void createTestTarget(std::string filepath)
{
  std::string s = FILE_START;
  int num = rand() % 20;
  for (int i=0; i < num; i++) {
    s += " -------------------------\n";
  }

  s += FILE_PART;

  num = rand() % 30;
  for (int i=0; i < num; i++) {
    s += "<<<<<<<<<<<<<<<<<<<<<<<<<<<\n";
  }

  writeTextFile(filepath, s);
}

class YARATest : public testing::Test {
 protected:
  void SetUp() override {
    auto mydir = fs::temp_directory_path() / "somedir";
    createDirectory(mydir, true, true);
    testTargetFile = (mydir / "yara-test-target.bin").string();

    removePath(testTargetFile);
    createTestTarget(testTargetFile);
    removePath(ruleFile);
    if (pathExists(ruleFile).ok()) {
      throw std::domain_error("Rule file exists.");
    }
  }

  void TearDown() override {
    removePath(ruleFile);
  }

  Row scanFileWithRulesFromFile(const std::string filename, const std::string& ruleContent) {
    YR_RULES* rules = nullptr;
    int result = yr_initialize();
    EXPECT_TRUE(result == ERROR_SUCCESS);

    writeTextFile(ruleFile, ruleContent);

    Status status = compileSingleFile(ruleFile, &rules);
    EXPECT_TRUE(status.ok());

    Row r;
    r["count"] = "0";
    r["matches"] = "";


    result = yr_rules_scan_file(
        rules, filename.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&r, 0);
    EXPECT_TRUE(result == ERROR_SUCCESS);

    yr_rules_destroy(rules);

    return r;
  }

  Row scanFileWithRulesFromString(const std::string filename, const std::string& ruleContent) {
    YR_RULES* rules = nullptr;
    int result = yr_initialize();
    EXPECT_TRUE(result == ERROR_SUCCESS);

    Row r = Row();
    r["count"] = "0";
    r["matches"] = "";

    Status status = compileRulesFromString(ruleContent, &rules);
    EXPECT_TRUE(status.ok());
    if (!status.ok() || rules == nullptr) {
      return r;
    }

    result = yr_rules_scan_file(
        rules, filename.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&r, 0);
    EXPECT_TRUE(result == ERROR_SUCCESS);

    yr_rules_destroy(rules);

    return r;
  }

};

TEST_F(YARATest, test_match_true) {
  Row r = scanFileWithRulesFromFile(testTargetFile, alwaysTrue);
  EXPECT_EQ("1",r["count"]);
}

TEST_F(YARATest, test_match_false) {
  Row r = scanFileWithRulesFromFile(testTargetFile, alwaysFalse);
  EXPECT_EQ("0",r["count"]);
}

TEST_F(YARATest, test_match) {
  Row r = scanFileWithRulesFromFile(testTargetFile, ruleShouldMatch);
  EXPECT_EQ("1",r["count"]);
  r = scanFileWithRulesFromString(testTargetFile, ruleShouldMatch);
  EXPECT_EQ("1",r["count"]);
}


TEST_F(YARATest, test_sql_siggroup_nosuch) {
  writeTextFile(ruleFile, ruleShouldMatch);

  std::string query = "SELECT * FROM yara WHERE path='" + testTargetFile;
  query += "' AND sig_group='no_such_group'";
  auto results = SQL(query);
  EXPECT_TRUE(results.getStatus().ok());
  EXPECT_EQ(0, results.rows().size());
}

TEST_F(YARATest, test_sql_sigfile) {
  writeTextFile(ruleFile, ruleShouldMatch);

  std::string query = "SELECT * FROM yara WHERE path='" + testTargetFile;
  query += "' AND sigfile='" + ruleFile + "'";
  auto results = SQL(query);
  if (!results.getStatus().ok()) {
    VLOG(1) << "SQL failed:" << results.getStatus().getMessage();
    return;
  }
  EXPECT_EQ(1, results.rows().size());

  // run again

  results = SQL(query);
  if (!results.getStatus().ok()) {
    VLOG(1) << "SQL failed:" << results.getStatus().getMessage();
    return;
  }
  EXPECT_EQ(1, results.rows().size());

}

TEST_F(YARATest, test_sql_adhoc_string) {
  std::string query = "SELECT * FROM yara WHERE path='" + testTargetFile;
  query += "' AND adhoc_rules='" + ruleShouldMatch + "'";
  auto results = SQL(query);
  if (!results.getStatus().ok()) {
    VLOG(1) << "SQL failed:" << results.getStatus().getMessage();
    return;
  }
  EXPECT_EQ(1, results.rows().size());

  // again!

  results = SQL(query);
  if (!results.getStatus().ok()) {
    VLOG(1) << "SQL failed:" << results.getStatus().getMessage();
    return;
  }
  EXPECT_EQ(1, results.rows().size());
}

TEST_F(YARATest, test_sql_adhoc_invalid_syntax) {
  std::string query = "SELECT * FROM yara WHERE path='" + testTargetFile;
  query += "' AND adhoc_rules='rule blah { strings: a=SOMETHING condition: a}'";
  auto results = SQL(query);
  if (!results.getStatus().ok()) {
    VLOG(1) << "SQL failed:" << results.getStatus().getMessage();
    return;
  }
  EXPECT_EQ(0, results.rows().size());
}

TEST_F(YARATest, test_path_pattern) {

  auto pathPattern = (fs::temp_directory_path() / "%" / "%.bin").string();
  writeTextFile(ruleFile, ruleShouldMatch);

  std::string query = "SELECT * FROM yara WHERE path LIKE '" + pathPattern;
    query += "' AND sigfile='" + ruleFile + "'";

  auto results = SQL(query);
  if (!results.getStatus().ok()) {
    VLOG(1) << "SQL failed:" << results.getStatus().getMessage();
    return;
  }
  EXPECT_EQ(1, results.rows().size());
}

class YaraConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {

    // config with valid syntax

    config_string_ = "{"
    "  \"yara\": {"
    "    \"signatures\": {"
    "      \"group1\": [ \"" + ruleFile + "\" ],"
    "      \"group2\": [ \"/tmp/some/non-existent/file.sig\" ]"
    "    }"
    "  }"
    "}";

    Config::get().reset();
  }

  void TearDown() override {
    Config::get().reset();
  }

 protected:
  std::string config_string_;
};

TEST_F(YaraConfigParserPluginTests, test_table_query) {
  writeTextFile(ruleFile, ruleShouldMatch);

  std::string query = "SELECT * FROM yara WHERE path='" + testTargetFile;
  query += "' AND sig_group='group1'";
  auto results = SQL(query);
  EXPECT_EQ(0, results.rows().size()); // no such group configured

  // load config

  std::map<std::string, std::string> tmp_config;
  tmp_config["yara_test_config"] = config_string_;
  Config::get().update(tmp_config);

  results = SQL(query);

  EXPECT_TRUE(results.getStatus().ok());
  EXPECT_EQ(1, results.rows().size());      // group now exists, expect match

  // try with group2, where sig file does not exist

  query = "SELECT * FROM yara WHERE path='" + testTargetFile;
  query += "' AND sig_group='group2'";

  results = SQL(query);

  EXPECT_TRUE(results.getStatus().ok());
  EXPECT_EQ(0, results.rows().size());
}

} // namespace osquery
