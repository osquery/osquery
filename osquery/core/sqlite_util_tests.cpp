/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include "osquery/core/sqlite_util.h"

#include <iostream>

#include <gtest/gtest.h>

#include "osquery/core/test_util.h"

namespace osquery {
namespace core {

class SQLiteUtilTests : public testing::Test {};

TEST_F(SQLiteUtilTests, test_simple_query_execution) {
  int err;
  auto db = createTestDB();
  auto results = query(kTestQuery, err, db);
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
  QueryData d = query(kTestQuery, err, db);
  sqlite3_close(db);
  EXPECT_EQ(err, 0);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
