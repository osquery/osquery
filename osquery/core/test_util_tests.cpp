/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <sqlite3.h>

#include <osquery/core.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace osquery {

class TestUtilTests : public testing::Test {};

TEST_F(TestUtilTests, test_expected_results) {
  int err;
  auto db = createTestDB();
  auto results = query(kTestQuery, err, db);
  sqlite3_close(db);
  EXPECT_EQ(err, 0);
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(TestUtilTests, test_get_test_db_result_stream) {
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
    int err_int;
    auto expected = query(kTestQuery, err_int, db);
    EXPECT_EQ(expected, r.second);
  }
  sqlite3_close(db);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
