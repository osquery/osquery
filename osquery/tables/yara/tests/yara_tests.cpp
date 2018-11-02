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
static void createTestTarget()
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

  writeTextFile(testTargetFile, s);
}

class YARATest : public testing::Test {
 protected:
  void SetUp() override {
    testTargetFile = (fs::temp_directory_path() / "yara-test-target.bin").string();
    removePath(testTargetFile);
    createTestTarget();
    removePath(ruleFile);
    if (pathExists(ruleFile).ok()) {
      throw std::domain_error("Rule file exists.");
    }
  }

  void TearDown() override {
    removePath(ruleFile);
  }

  Row scanFile(const std::string filename, const std::string& ruleContent) {
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
};

TEST_F(YARATest, test_match_true) {
  Row r = scanFile(testTargetFile, alwaysTrue);
  EXPECT_EQ("1",r["count"]);
}

TEST_F(YARATest, test_match_false) {
  Row r = scanFile(testTargetFile, alwaysFalse);
  EXPECT_EQ("0",r["count"]);
}

TEST_F(YARATest, test_match) {
  Row r = scanFile(testTargetFile, ruleShouldMatch);
  EXPECT_EQ("1",r["count"]);
}

} // namespace osquery
