/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/sql.h>

#include "osquery/core/test_util.h"
#include "osquery/sql/sqlite_util.h"

namespace osquery {

class SQLiteUtilTests : public testing::Test {};

sqlite3* createTestDB() {
  sqlite3* db = createDB();
  char* err = nullptr;
  std::vector<std::string> queries = {
      "CREATE TABLE test_table ("
      "username varchar(30) primary key, "
      "age int"
      ")",
      "INSERT INTO test_table VALUES (\"mike\", 23)",
      "INSERT INTO test_table VALUES (\"matt\", 24)"};
  for (auto q : queries) {
    sqlite3_exec(db, q.c_str(), nullptr, nullptr, &err);
    if (err != nullptr) {
      return nullptr;
    }
  }

  return db;
}

TEST_F(SQLiteUtilTests, test_simple_query_execution) {
  auto db = createTestDB();
  QueryData results;
  auto status = queryInternal(kTestQuery, results, db);
  sqlite3_close(db);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_passing_callback_no_data_param) {
  char* err = nullptr;
  auto db = createTestDB();
  sqlite3_exec(db, kTestQuery.c_str(), queryDataCallback, nullptr, &err);
  sqlite3_close(db);
  EXPECT_TRUE(err != nullptr);
  if (err != nullptr) {
    sqlite3_free(err);
  }
}

TEST_F(SQLiteUtilTests, test_aggregate_query) {
  auto db = createTestDB();
  QueryData results;
  auto status = queryInternal(kTestQuery, results, db);
  sqlite3_close(db);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_get_test_db_result_stream) {
  auto db = createTestDB();
  auto results = getTestDBResultStream();
  for (auto r : results) {
    char* err_char = nullptr;
    sqlite3_exec(db, (r.first).c_str(), nullptr, nullptr, &err_char);
    EXPECT_TRUE(err_char == nullptr);
    if (err_char != nullptr) {
      sqlite3_free(err_char);
      ASSERT_TRUE(false);
    }

    QueryData expected;
    auto status = queryInternal(kTestQuery, expected, db);
    EXPECT_EQ(expected, r.second);
  }
  sqlite3_close(db);
}

TEST_F(SQLiteUtilTests, test_get_query_columns) {
  std::unique_ptr<sqlite3, decltype(sqlite3_close)*> db_managed(createDB(),
                                                                sqlite3_close);
  sqlite3* db = db_managed.get();

  std::string query;
  Status status;
  tables::TableColumns results;

  query =
      "SELECT hour, minutes, seconds, version, config_md5, config_path, \
           pid FROM time JOIN osquery_info";
  status = getQueryColumnsInternal(query, results, db);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(7, results.size());
  EXPECT_EQ(std::make_pair(std::string("hour"), std::string("INTEGER")),
            results[0]);
  EXPECT_EQ(std::make_pair(std::string("minutes"), std::string("INTEGER")),
            results[1]);
  EXPECT_EQ(std::make_pair(std::string("seconds"), std::string("INTEGER")),
            results[2]);
  EXPECT_EQ(std::make_pair(std::string("version"), std::string("TEXT")),
            results[3]);
  EXPECT_EQ(std::make_pair(std::string("config_md5"), std::string("TEXT")),
            results[4]);
  EXPECT_EQ(std::make_pair(std::string("config_path"), std::string("TEXT")),
            results[5]);
  EXPECT_EQ(std::make_pair(std::string("pid"), std::string("INTEGER")),
            results[6]);

  query = "SELECT hour + 1 AS hour1, minutes + 1 FROM time";
  status = getQueryColumnsInternal(query, results, db);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(2, results.size());
  EXPECT_EQ(std::make_pair(std::string("hour1"), std::string("UNKNOWN")),
            results[0]);
  EXPECT_EQ(std::make_pair(std::string("minutes + 1"), std::string("UNKNOWN")),
            results[1]);

  query = "SELECT * FROM foo";
  status = getQueryColumnsInternal(query, results, db);
  ASSERT_FALSE(status.ok());
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
