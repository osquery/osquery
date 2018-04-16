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

#include <osquery/database.h>

#include "osquery/core/json.h"
#include "osquery/tests/test_util.h"

#include <osquery/logger.h>

namespace rj = rapidjson;

namespace osquery {

class DatabaseTests : public testing::Test {};

TEST_F(DatabaseTests, test_set_value) {
  auto s = setDatabaseValue(kLogs, "i", "{}");
  EXPECT_TRUE(s.ok());
}

TEST_F(DatabaseTests, test_get_value) {
  std::string expected{"{}"};
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

TEST_F(DatabaseTests, test_ptree_upgraded_to_rj) {
  auto bad_json =
      "{\"\":{\"disabled\":\"0\",\"network_name\":\"BTWifi-Starbucks\"},\"\":{"
      "\"disabled\":\"0\",\"network_name\":\"Lobo-Guest\"},\"\":{\"disabled\":"
      "\"0\",\"network_name\":\"GoogleGuest\"}}";
  auto status = setDatabaseValue(kQueries, "bad_wifi_json", bad_json);
  EXPECT_TRUE(status.ok());

  // Add an integer value to ensure we don't munge non-json objects
  status = setDatabaseValue(kQueries, "bad_wifi_jsonepoch", "1521583712");

  rj::Document bad_doc;

  // Potential bug with RJ, in that parsing should fail with empty keys
  // EXPECT_TRUE(bad_doc.Parse(bad_json).HasParseError());
  EXPECT_FALSE(bad_doc.IsArray());

  status = upgradeDatabase();
  EXPECT_TRUE(status.ok());

  std::string good_json;
  status = getDatabaseValue(kQueries, "bad_wifi_json", good_json);
  EXPECT_TRUE(status.ok());

  rj::Document clean_doc;
  EXPECT_FALSE(clean_doc.Parse(good_json).HasParseError());
  EXPECT_TRUE(clean_doc.IsArray());
  EXPECT_EQ(clean_doc.Size(), 3U);

  // Ensure our non-json thing was not destroyed
  std::string query_epoch{""};
  status = getDatabaseValue(kQueries, "bad_wifi_jsonepoch", query_epoch);
  LOG(INFO) << query_epoch;
  auto ulepoch = std::stoull(query_epoch);
  EXPECT_EQ(ulepoch, 1521583712U);
}
}
