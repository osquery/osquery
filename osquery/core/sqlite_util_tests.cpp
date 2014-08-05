// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <iostream>

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/sqlite_util.h"
#include "osquery/core/test_util.h"

using namespace osquery::core;
using namespace osquery::db;

class SQLiteUtilTests : public testing::Test {};

TEST_F(SQLiteUtilTests, test_simple_query_execution) {
  int err;
  auto results = aggregateQuery(kTestQuery, err, createTestDB());
  EXPECT_EQ(err, 0);
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_passing_callback_no_data_param) {
  char *err = nullptr;
  sqlite3_exec(createTestDB(), kTestQuery.c_str(), query_data_callback, nullptr, &err);
  EXPECT_TRUE(err != nullptr);
  if (err != nullptr) {
    sqlite3_free(err);
  }
}

TEST_F(SQLiteUtilTests, test_aggregate_query) {
  int err;
  QueryData d = aggregateQuery(kTestQuery, err, createTestDB());
  EXPECT_EQ(err, 0);
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
