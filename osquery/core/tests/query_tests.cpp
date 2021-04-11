/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <ctime>
#include <deque>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/core/query.h>
#include <osquery/core/sql/scheduled_query.h>
#include <osquery/core/system.h>
#include <osquery/sql/tests/sql_test_utils.h>
#include <osquery/tests/test_util.h>

namespace osquery {

DECLARE_bool(disable_database);
DECLARE_bool(logger_numerics);

class QueryTests : public testing::Test {
 public:
  QueryTests() {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(QueryTests, test_private_members) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  EXPECT_EQ(cf.query_, query.query);
}

TEST_F(QueryTests, test_increment_counter) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);

  uint64_t counter = 1;
  auto status = cf.incrementCounter(true, counter);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(0, counter);

  status = cf.incrementCounter(false, counter);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(1, counter);
}

TEST_F(QueryTests, test_get_query_status) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("query_status", query);

  // We have never seen this query before (it has no results yet either).
  bool fresh_results = false;
  bool new_query = false;
  cf.getQueryStatus(100, fresh_results, new_query);
  EXPECT_TRUE(fresh_results);
  EXPECT_TRUE(new_query);

  // Add results for this query (this action is not under test).
  uint64_t counter = 0;
  auto status = cf.addNewResults(getTestDBExpectedResults(), 100, counter);
  ASSERT_TRUE(status.ok());

  // The query has results and the query text has not changed.
  fresh_results = false;
  new_query = false;
  cf.getQueryStatus(100, fresh_results, new_query);
  EXPECT_FALSE(fresh_results);
  EXPECT_FALSE(new_query);

  // The epoch changed so the previous results are invalid.
  fresh_results = false;
  new_query = false;
  cf.getQueryStatus(101, fresh_results, new_query);
  EXPECT_TRUE(fresh_results);
  EXPECT_FALSE(new_query);

  // Add results for the new epoch (this action is not under test).
  status = cf.addNewResults(getTestDBExpectedResults(), 101, counter);
  ASSERT_TRUE(status.ok());

  // The epoch is the same but the query text has changed.
  fresh_results = false;
  new_query = false;
  query.query += " LIMIT 1";
  auto cf2 = Query("query_status", query);
  cf2.getQueryStatus(101, fresh_results, new_query);
  EXPECT_FALSE(fresh_results);
  EXPECT_TRUE(new_query);
}

TEST_F(QueryTests, test_add_and_get_current_results) {
  FLAGS_logger_numerics = true;
  // Test adding a "current" set of results to a scheduled query instance.
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  uint64_t counter = 128;
  auto status = cf.addNewResults(getTestDBExpectedResults(), 0, counter);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(status.toString(), "OK");
  EXPECT_EQ(counter, 0UL);

  // Simulate results from several schedule runs, calculate differentials.
  uint64_t expected_counter = counter + 1;
  for (auto result : getTestDBResultStream()) {
    // Get the results from the previous query execution (from the DB).
    QueryDataSet previous_qd;
    status = cf.getPreviousQueryResults(previous_qd);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(status.toString(), "OK");

    // Add the "current" results and output the differentials.
    DiffResults dr;
    counter = 128;
    auto s = cf.addNewResults(result.second, 0, counter, dr, true);
    EXPECT_TRUE(s.ok());
    EXPECT_EQ(counter, expected_counter++);

    // Call the diffing utility directly.
    DiffResults expected = diff(previous_qd, result.second);
    EXPECT_EQ(dr, expected);

    // After Query::addNewResults the previous results are now current.
    QueryDataSet qds_previous;
    cf.getPreviousQueryResults(qds_previous);

    QueryDataSet qds;
    for (auto& i : result.second) {
      qds.insert(i);
    }

    EXPECT_EQ(qds_previous, qds);
  }
}

TEST_F(QueryTests, test_get_query_results) {
  // Grab an expected set of query data and add it as the previous result.
  auto encoded_qd = getSerializedQueryDataJSON();
  auto query = getOsqueryScheduledQuery();
  auto status = setDatabaseValue(kQueries, "foobar", encoded_qd.first);
  EXPECT_TRUE(status.ok());

  // Use the Query retrieval API to check the now "previous" result.
  QueryDataSet previous_qd;
  auto cf = Query("foobar", query);
  status = cf.getPreviousQueryResults(previous_qd);
  EXPECT_TRUE(status.ok());
}

TEST_F(QueryTests, test_query_name_not_found_in_db) {
  // Try to retrieve results from a query that has not executed.
  QueryDataSet previous_qd;
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("not_a_real_query", query);
  auto status = cf.getPreviousQueryResults(previous_qd);
  EXPECT_FALSE(status.ok());
  EXPECT_TRUE(previous_qd.empty());
}

TEST_F(QueryTests, test_is_query_name_in_database) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  auto encoded_qd = getSerializedQueryDataJSON();
  auto status = setDatabaseValue(kQueries, "foobar", encoded_qd.first);
  EXPECT_TRUE(status.ok());
  // Now test that the query name exists.
  EXPECT_TRUE(cf.isQueryNameInDatabase());
}

TEST_F(QueryTests, test_query_name_updated) {
  // Try to retrieve results from a query that has not executed.
  QueryDataSet previous_qd;
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("will_update_query", query);
  EXPECT_TRUE(cf.isNewQuery());
  EXPECT_TRUE(cf.isNewQuery());

  DiffResults dr;
  uint64_t counter = 128;
  auto results = getTestDBExpectedResults();
  cf.addNewResults(results, 0, counter, dr);
  EXPECT_FALSE(cf.isNewQuery());
  EXPECT_EQ(counter, 0UL);

  query.query += " LIMIT 1";
  counter = 128;
  auto cf2 = Query("will_update_query", query);
  EXPECT_TRUE(cf2.isQueryNameInDatabase());
  EXPECT_TRUE(cf2.isNewQuery());
  cf2.addNewResults(results, 0, counter, dr);
  EXPECT_FALSE(cf2.isNewQuery());
  EXPECT_EQ(counter, 0UL);
}

TEST_F(QueryTests, test_get_stored_query_names) {
  auto query = getOsqueryScheduledQuery();
  auto cf = Query("foobar", query);
  auto encoded_qd = getSerializedQueryDataJSON();
  auto status = setDatabaseValue(kQueries, "foobar", encoded_qd.first);
  EXPECT_TRUE(status.ok());

  // Stored query names is a factory method included alongside every query.
  // It will include the set of query names with existing "previous" results.
  auto names = cf.getStoredQueryNames();
  auto in_vector = std::find(names.begin(), names.end(), "foobar");
  EXPECT_NE(in_vector, names.end());
}

TEST_F(QueryTests, test_is_snapshot_query) {
  auto sq = ScheduledQuery();

  // If the snapshot option is not set, this is not a snapshot query.
  EXPECT_FALSE(sq.isSnapshotQuery());

  sq.options["snapshot"] = true;
  EXPECT_TRUE(sq.isSnapshotQuery());

  sq.options["snapshot"] = false;
  EXPECT_FALSE(sq.isSnapshotQuery());
}

TEST_F(QueryTests, test_report_removed_rows) {
  auto sq = ScheduledQuery();

  // If the removed option is not set, removed rows should be reported.
  EXPECT_TRUE(sq.reportRemovedRows());

  sq.options["removed"] = true;
  EXPECT_TRUE(sq.reportRemovedRows());

  sq.options["removed"] = false;
  EXPECT_FALSE(sq.reportRemovedRows());
}
}
