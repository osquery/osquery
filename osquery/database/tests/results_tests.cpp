/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

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

TEST_F(ResultsTests, test_deserialize_row_json) {
  auto results = getSerializedRow();
  std::string input;
  serializeRowJSON(results.second, input);

  // Pull the serialized JSON back into a Row output container.
  Row output;
  auto s = deserializeRowJSON(input, output);
  EXPECT_TRUE(s.ok());
  // The output container should match the input row.
  EXPECT_EQ(output, results.second);
}

TEST_F(ResultsTests, test_serialize_query_data) {
  auto results = getSerializedQueryData();
  pt::ptree tree;
  auto s = serializeQueryData(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_query_data_json) {
  auto results = getSerializedQueryDataJSON();
  std::string json;
  auto s = serializeQueryDataJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_deserialize_query_data_json) {
  auto results = getSerializedQueryDataJSON();

  // Pull the serialized JSON back into a QueryData output container.
  QueryData output;
  auto s = deserializeQueryDataJSON(results.first, output);
  EXPECT_TRUE(s.ok());
  // The output container should match the input query data.
  EXPECT_EQ(output, results.second);
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

TEST_F(ResultsTests, test_serialize_query_log_item) {
  auto results = getSerializedQueryLogItem();
  pt::ptree tree;
  auto s = serializeQueryLogItem(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_query_log_item_json) {
  auto results = getSerializedQueryLogItemJSON();
  std::string json;
  auto s = serializeQueryLogItemJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_deserialize_query_log_item_json) {
  auto results = getSerializedQueryLogItemJSON();

  // Pull the serialized JSON back into a QueryLogItem output container.
  QueryLogItem output;
  auto s = deserializeQueryLogItemJSON(results.first, output);
  EXPECT_TRUE(s.ok());
  // The output container should match the input query data.
  EXPECT_EQ(output, results.second);
}

TEST_F(ResultsTests, test_serialize_distributed_query_request) {
  DistributedQueryRequest r;
  r.query = "foo";
  r.id = "bar";

  pt::ptree tree;
  auto s = serializeDistributedQueryRequest(r, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(tree.get<std::string>("query"), "foo");
  EXPECT_EQ(tree.get<std::string>("id"), "bar");
}

TEST_F(ResultsTests, test_deserialize_distributed_query_request) {
  pt::ptree tree;
  tree.put<std::string>("query", "foo");
  tree.put<std::string>("id", "bar");

  DistributedQueryRequest r;
  auto s = deserializeDistributedQueryRequest(tree, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(r.query, "foo");
  EXPECT_EQ(r.id, "bar");
}

TEST_F(ResultsTests, test_deserialize_distributed_query_request_json) {
  auto json =
      "{"
      "  \"query\": \"foo\","
      "  \"id\": \"bar\""
      "}";

  DistributedQueryRequest r;
  auto s = deserializeDistributedQueryRequestJSON(json, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(r.query, "foo");
  EXPECT_EQ(r.id, "bar");
}

TEST_F(ResultsTests, test_serialize_distributed_query_result) {
  DistributedQueryResult r;
  r.request.query = "foo";
  r.request.id = "bar";

  Row r1;
  r1["foo"] = "bar";
  r.results = {r1};

  pt::ptree tree;
  auto s = serializeDistributedQueryResult(r, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(tree.get<std::string>("request.query"), "foo");
  EXPECT_EQ(tree.get<std::string>("request.id"), "bar");
  auto& results = tree.get_child("results");
  for (const auto& q : results) {
    for (const auto& row : q.second) {
      EXPECT_EQ(row.first, "foo");
      EXPECT_EQ(q.second.get<std::string>(row.first), "bar");
    }
  }
}

TEST_F(ResultsTests, test_deserialize_distributed_query_result) {
  pt::ptree request;
  request.put<std::string>("id", "foo");
  request.put<std::string>("query", "bar");

  pt::ptree row;
  row.put<std::string>("foo", "bar");
  pt::ptree results;
  results.push_back(std::make_pair("", row));

  pt::ptree query_result;
  query_result.put_child("request", request);
  query_result.put_child("results", results);

  DistributedQueryResult r;
  auto s = deserializeDistributedQueryResult(query_result, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(r.request.id, "foo");
  EXPECT_EQ(r.request.query, "bar");
  EXPECT_EQ(r.results[0]["foo"], "bar");
}

TEST_F(ResultsTests, test_deserialize_distributed_query_result_json) {
  auto json =
      "{"
      "  \"request\": {"
      "    \"id\": \"foo\","
      "    \"query\": \"bar\""
      "  },"
      "  \"results\": ["
      "    {"
      "      \"foo\": \"bar\""
      "    }"
      "  ]"
      "}";

  DistributedQueryResult r;
  auto s = deserializeDistributedQueryResultJSON(json, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(r.request.id, "foo");
  EXPECT_EQ(r.request.query, "bar");
  EXPECT_EQ(r.results[0]["foo"], "bar");
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
  EXPECT_EQ(q.size(), 1U);

  s = addUniqueRowToQueryData(q, r2);
  EXPECT_TRUE(s);
  EXPECT_EQ(q.size(), 2U);

  s = addUniqueRowToQueryData(q, r3);
  EXPECT_FALSE(s);
  EXPECT_EQ(q.size(), 2U);
}
}
