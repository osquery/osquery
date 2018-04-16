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

namespace osquery {

const std::string ruleFile{"/tmp/osquery-yara.sig"};
const std::string ls{"/bin/ls"};
const std::string alwaysTrue{"rule always_true { condition: true }"};
const std::string alwaysFalse{"rule always_false { condition: false }"};

class YARATest : public testing::Test {
 protected:
  void SetUp() override {
    removePath(ruleFile);
    if (pathExists(ruleFile).ok()) {
      throw std::domain_error("Rule file exists.");
    }
  }

  void TearDown() override {
    removePath(ruleFile);
  }

  Row scanFile(const std::string& ruleContent) {
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
        rules, ls.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&r, 0);
    EXPECT_TRUE(result == ERROR_SUCCESS);

    yr_rules_destroy(rules);

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
} // namespace osquery
