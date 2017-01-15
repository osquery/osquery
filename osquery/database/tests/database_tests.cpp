/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/database.h>

#include "osquery/tests/test_util.h"

namespace osquery {

class DatabaseTests : public testing::Test {};

TEST_F(DatabaseTests, test_set_value) {
  auto s = setDatabaseValue(kLogs, "i", "{}");
  EXPECT_TRUE(s.ok());
}

TEST_F(DatabaseTests, test_get_value) {
  std::string expected = "{}";
  setDatabaseValue(kLogs, "i", expected);

  std::string value;
  auto s = getDatabaseValue(kLogs, "i", value);

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, expected);

  // Unknown keys return failed, but will return empty data.
  value.clear();
  s = getDatabaseValue(kLogs, "does_not_exist", value);
  EXPECT_FALSE(s.ok());
  EXPECT_TRUE(value.empty());
}

TEST_F(DatabaseTests, test_scan_values) {
  setDatabaseValue(kLogs, "1", "0");
  setDatabaseValue(kLogs, "2", "0");
  setDatabaseValue(kLogs, "3", "0");

  std::vector<std::string> keys;
  auto s = scanDatabaseKeys(kLogs, keys);
  EXPECT_TRUE(s.ok());
  EXPECT_GT(keys.size(), 2U);

  keys.clear();
  s = scanDatabaseKeys(kLogs, keys, 2);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(keys.size(), 2U);
}

TEST_F(DatabaseTests, test_delete_values) {
  setDatabaseValue(kLogs, "k", "0");

  std::string value;
  getDatabaseValue(kLogs, "k", value);
  EXPECT_FALSE(value.empty());

  auto s = deleteDatabaseValue(kLogs, "k");
  EXPECT_TRUE(s.ok());

  // Make sure the key has been deleted.
  value.clear();
  s = getDatabaseValue(kLogs, "k", value);
  EXPECT_FALSE(s.ok());
  EXPECT_TRUE(value.empty());
}

TEST_F(DatabaseTests, test_reset) {
  setDatabaseValue(kLogs, "reset", "1");
  resetDatabase();

  std::string value;
  EXPECT_TRUE(getDatabaseValue(kLogs, "reset", value));
  EXPECT_EQ(value, "1");
}
}
