// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/core/sqlite_util.h"

#include <iostream>

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/test_util.h"

using namespace osquery::core;
using namespace osquery::db;

class SQLiteUtilTests : public testing::Test {};

TEST_F(SQLiteUtilTests, test_simple_query_execution) {
  int err;
  auto db = createTestDB();
  auto results = aggregateQuery(kTestQuery, err, db);
  sqlite3_close(db);
  EXPECT_EQ(err, 0);
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_passing_callback_no_data_param) {
  char* err = nullptr;
  auto db = createTestDB();
  sqlite3_exec(db, kTestQuery.c_str(), query_data_callback, nullptr, &err);
  sqlite3_close(db);
  EXPECT_TRUE(err != nullptr);
  if (err != nullptr) {
    sqlite3_free(err);
  }
}

TEST_F(SQLiteUtilTests, test_aggregate_query) {
  int err;
  auto db = createTestDB();
  QueryData d = aggregateQuery(kTestQuery, err, db);
  sqlite3_close(db);
  EXPECT_EQ(err, 0);
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
