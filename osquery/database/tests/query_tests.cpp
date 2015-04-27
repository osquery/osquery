/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <ctime>
#include <deque>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/database/query.h>

#include "osquery/core/test_util.h"

const std::string kTestingQueryDBPath = "/tmp/rocksdb-osquery-querytests";

namespace osquery {

class QueryTests : public testing::Test {
 public:
  void SetUp() { db_ = DBHandle::getInstanceAtPath(kTestingQueryDBPath); }
  void TearDown() { boost::filesystem::remove_all(kTestingQueryDBPath); }

 public:
  std::shared_ptr<DBHandle> db_;
};

TEST_F(QueryTests, test_get_column_family_name) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  EXPECT_EQ(cf.getQueryName(), "foobar");
}

TEST_F(QueryTests, test_get_query) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  EXPECT_EQ(cf.getQuery(), query.query);
}

TEST_F(QueryTests, test_get_interval) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  EXPECT_EQ(cf.getInterval(), query.interval);
}

TEST_F(QueryTests, test_private_members) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  EXPECT_EQ(cf.query_, query);
}

TEST_F(QueryTests, test_add_and_get_current_results) {
  // Test adding a "current" set of results to a scheduled query instance.
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  auto status = cf.addNewResults(getTestDBExpectedResults(), db_);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(status.toString(), "OK");

  // Simulate results from several schedule runs, calculate differentials.
  for (auto result : getTestDBResultStream()) {
    // Get the results from the previous query execution (from RocksDB).
    QueryData previous_qd;
    auto status = cf.getPreviousQueryResults(previous_qd, db_);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(status.toString(), "OK");

    // Add the "current" results and output the differentials.
    DiffResults dr;
    auto s = cf.addNewResults(result.second, dr, true, db_);
    EXPECT_TRUE(s.ok());

    // Call the diffing utility directly.
    DiffResults expected = diff(previous_qd, result.second);
    EXPECT_EQ(dr, expected);

    // After Query::addNewResults the previous results are now current.
    QueryData qd;
    cf.getPreviousQueryResults(qd, db_);
    EXPECT_EQ(qd, result.second);
  }
}

TEST_F(QueryTests, test_get_query_results) {
  // Grab an expected set of query data and add it as the previous result.
  auto encoded_qd = getSerializedQueryDataJSON();
  auto query = getOsqueryScheduledQuery();
  auto status = db_->Put(kQueries, "foobar", encoded_qd.first);
  EXPECT_TRUE(status.ok());

  // Use the Query retrieval API to check the now "previous" result.
  QueryData previous_qd;
  auto cf = Query("foobar", query);
  status = cf.getPreviousQueryResults(previous_qd, db_);
  EXPECT_TRUE(status.ok());
}

TEST_F(QueryTests, test_query_name_not_found_in_db) {
  // Try to retrieve results from a query that has not executed.
  QueryData previous_qd;
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("not_a_real_query", query);
  auto status = cf.getPreviousQueryResults(previous_qd, db_);
  EXPECT_FALSE(status.ok());
}

TEST_F(QueryTests, test_is_query_name_in_database) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  auto encoded_qd = getSerializedQueryDataJSON();
  auto status = db_->Put(kQueries, "foobar", encoded_qd.first);
  EXPECT_TRUE(status.ok());
  // Now test that the query name exists.
  EXPECT_TRUE(cf.isQueryNameInDatabase(db_));
}

TEST_F(QueryTests, test_get_stored_query_names) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  auto encoded_qd = getSerializedQueryDataJSON();
  auto status = db_->Put(kQueries, "foobar", encoded_qd.first);
  EXPECT_TRUE(status.ok());

  // Stored query names is a factory method included alongside every query.
  // It will include the set of query names with existing "previous" results.
  auto names = cf.getStoredQueryNames(db_);
  auto in_vector = std::find(names.begin(), names.end(), "foobar");
  EXPECT_NE(in_vector, names.end());
}
}
