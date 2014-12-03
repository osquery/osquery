// Copyright 2004-present Facebook. All Rights Reserved.

#include <sstream>
#include <string>
#include <vector>

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <osquery/database/results.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

using namespace osquery::core;

namespace osquery {

class ResultsTests : public testing::Test {};

TEST_F(ResultsTests, test_simple_diff) {
  QueryData o;
  QueryData n;

  Row r1;
  r1["foo"] = "bar";
  n.push_back(r1);

  auto results = diff(o, n);
  EXPECT_EQ(results.added, n);
  EXPECT_EQ(results.removed, o);
}

TEST_F(ResultsTests, test_serialize_row) {
  auto results = getSerializedRow();
  pt::ptree tree;
  auto s = serializeRow(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_query_data) {
  auto results = getSerializedQueryData();
  pt::ptree tree;
  auto s = serializeQueryData(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_diff_results) {
  auto results = getSerializedDiffResults();
  pt::ptree tree;
  auto s = serializeDiffResults(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_diff_results_json) {
  auto results = getSerializedDiffResultsJSON();
  std::string json;
  auto s = serializeDiffResultsJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_serialize_historical_query_results) {
  auto results = getSerializedHistoricalQueryResults();
  pt::ptree tree;
  auto s = serializeHistoricalQueryResults(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_historical_query_results_json) {
  auto results = getSerializedHistoricalQueryResultsJSON();
  std::string json;
  auto s = serializeHistoricalQueryResultsJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_deserialize_historical_query_results) {
  auto results = getSerializedHistoricalQueryResults();
  HistoricalQueryResults r;
  auto s = deserializeHistoricalQueryResults(results.first, r);
  EXPECT_EQ(results.second, r);
  EXPECT_EQ(results.second.mostRecentResults, r.mostRecentResults);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(ResultsTests, test_deserialize_historical_query_results_json) {
  auto results = getSerializedHistoricalQueryResultsJSON();
  HistoricalQueryResults r;
  auto s = deserializeHistoricalQueryResultsJSON(results.first, r);
  EXPECT_EQ(results.second, r);
  EXPECT_EQ(results.second.mostRecentResults, r.mostRecentResults);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(ResultsTests, test_serialize_scheduled_query_log_item) {
  auto results = getSerializedScheduledQueryLogItem();
  pt::ptree tree;
  auto s = serializeScheduledQueryLogItem(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_scheduled_query_log_item_json) {
  auto results = getSerializedScheduledQueryLogItemJSON();
  std::string json;
  auto s = serializeScheduledQueryLogItemJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_adding_duplicate_rows_to_query_data) {
  Row r1, r2, r3;
  r1["foo"] = "bar";
  r1["baz"] = "boo";

  r2["foo"] = "baz";
  r2["baz"] = "bop";

  r3["foo"] = "baz";
  r3["baz"] = "bop";

  QueryData q;
  bool s;

  s = addUniqueRowToQueryData(q, r1);
  EXPECT_TRUE(s);
  EXPECT_EQ(q.size(), 1);

  s = addUniqueRowToQueryData(q, r2);
  EXPECT_TRUE(s);
  EXPECT_EQ(q.size(), 2);

  s = addUniqueRowToQueryData(q, r3);
  EXPECT_FALSE(s);
  EXPECT_EQ(q.size(), 2);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
