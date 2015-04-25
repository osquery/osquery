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

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/sql.h>

#include "osquery/distributed/distributed.h"
#include "osquery/sql/sqlite_util.h"

namespace pt = boost::property_tree;

namespace osquery {

// Distributed tests expect an SQL implementation for queries.
REGISTER_INTERNAL(SQLiteSQLPlugin, "sql", "sql");

class DistributedTests : public testing::Test {};

TEST_F(DistributedTests, test_test_distributed_provider) {
  MockDistributedProvider p;
  std::string query_string = "['foo']";
  std::string result_string = "['bar']";

  p.queriesJSON_ = query_string;
  std::string query_json;
  Status s = p.getQueriesJSON(query_json);
  ASSERT_EQ(Status(), s);
  EXPECT_EQ(query_string, query_json);

  s = p.writeResultsJSON(result_string);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(result_string, p.resultsJSON_);
}

TEST_F(DistributedTests, test_parse_query_json) {
  // clang-format off
  std::string request_json = R"([{"query": "foo", "id": "bar"}])";
  // clang-format on
  std::vector<DistributedQueryRequest> requests;
  Status s = DistributedQueryHandler::parseQueriesJSON(request_json, requests);
  ASSERT_EQ(Status(), s);
  EXPECT_EQ(1, requests.size());
  EXPECT_EQ("foo", requests[0].query);
  EXPECT_EQ("bar", requests[0].id);

  // clang-format off
  std::string bad_json = R"([{"query": "foo", "id": "bar"}, {"query": "b"}])";
  // clang-format on
  requests.clear();
  s = DistributedQueryHandler::parseQueriesJSON(bad_json, requests);
  ASSERT_FALSE(s.ok());
  EXPECT_EQ(0, requests.size());
}

TEST_F(DistributedTests, test_handle_query) {
  // Access to the internal SQL implementation is only available in core.
  SQL query = DistributedQueryHandler::handleQuery("SELECT hour from time");
  ASSERT_TRUE(query.ok());
  QueryData rows = query.rows();
  ASSERT_EQ(1, rows.size());
  EXPECT_EQ(rows[0]["_source_host"], getHostname());

  query = DistributedQueryHandler::handleQuery("bad query");
  ASSERT_FALSE(query.ok());
  rows = query.rows();
  ASSERT_EQ(0, rows.size());
}

TEST_F(DistributedTests, test_serialize_results_empty) {
  DistributedQueryRequest r0("foo", "foo_id");
  MockSQL q0 = MockSQL();
  pt::ptree tree;

  DistributedQueryHandler::serializeResults({{r0, q0}}, tree);

  EXPECT_EQ(0, tree.get<int>("results.foo_id.status"));
  EXPECT_TRUE(tree.get_child("results.foo_id.rows").empty());
}

TEST_F(DistributedTests, test_serialize_results_basic) {
  DistributedQueryRequest r0("foo", "foo_id");
  QueryData rows0 = {
      {{"foo0", "foo0_val"}, {"bar0", "bar0_val"}},
      {{"foo1", "foo1_val"}, {"bar1", "bar1_val"}},
  };
  MockSQL q0 = MockSQL(rows0);
  pt::ptree tree;

  DistributedQueryHandler::serializeResults({{r0, q0}}, tree);

  EXPECT_EQ(0, tree.get<int>("results.foo_id.status"));

  const pt::ptree& tree_rows = tree.get_child("results.foo_id.rows");
  EXPECT_EQ(2, tree_rows.size());

  auto row = tree_rows.begin();
  EXPECT_EQ("foo0_val", row->second.get<std::string>("foo0"));
  EXPECT_EQ("bar0_val", row->second.get<std::string>("bar0"));
  ++row;
  EXPECT_EQ("foo1_val", row->second.get<std::string>("foo1"));
  EXPECT_EQ("bar1_val", row->second.get<std::string>("bar1"));
}

TEST_F(DistributedTests, test_serialize_results_multiple) {
  DistributedQueryRequest r0("foo", "foo_id");
  QueryData rows0 = {
      {{"foo0", "foo0_val"}, {"bar0", "bar0_val"}},
      {{"foo1", "foo1_val"}, {"bar1", "bar1_val"}},
  };
  MockSQL q0 = MockSQL(rows0);

  DistributedQueryRequest r1("bar", "bar_id");
  MockSQL q1 = MockSQL({}, Status(1, "Fail"));

  pt::ptree tree;

  DistributedQueryHandler::serializeResults({{r0, q0}, {r1, q1}}, tree);

  EXPECT_EQ(0, tree.get<int>("results.foo_id.status"));
  const pt::ptree& tree_rows = tree.get_child("results.foo_id.rows");
  EXPECT_EQ(2, tree_rows.size());
  auto row = tree_rows.begin();
  EXPECT_EQ("foo0_val", row->second.get<std::string>("foo0"));
  EXPECT_EQ("bar0_val", row->second.get<std::string>("bar0"));
  ++row;
  EXPECT_EQ("foo1_val", row->second.get<std::string>("foo1"));
  EXPECT_EQ("bar1_val", row->second.get<std::string>("bar1"));

  EXPECT_EQ(1, tree.get<int>("results.bar_id.status"));
  const pt::ptree& fail_rows = tree.get_child("results.bar_id.rows");
  EXPECT_EQ(0, fail_rows.size());
}

TEST_F(DistributedTests, test_do_queries) {
  // Access to the internal SQL implementation is only available in core.
  auto provider_raw = new MockDistributedProvider();
  provider_raw->queriesJSON_ =
    R"([
      {"query": "SELECT hour FROM time", "id": "hour"},
      {"query": "bad", "id": "bad"},
      {"query": "SELECT minutes FROM time", "id": "minutes"}
    ])";
  std::unique_ptr<MockDistributedProvider>
    provider(provider_raw);
  DistributedQueryHandler handler(std::move(provider));

  Status s = handler.doQueries();
  ASSERT_EQ(Status(), s);

  pt::ptree tree;
  std::istringstream json_stream(provider_raw->resultsJSON_);
  ASSERT_NO_THROW(pt::read_json(json_stream, tree));

  {
    EXPECT_EQ(0, tree.get<int>("results.hour.status"));
    const pt::ptree& tree_rows = tree.get_child("results.hour.rows");
    EXPECT_EQ(1, tree_rows.size());
    auto row = tree_rows.begin();
    EXPECT_GE(row->second.get<int>("hour"), 0);
    EXPECT_LE(row->second.get<int>("hour"), 24);
    EXPECT_EQ(getHostname(), row->second.get<std::string>("_source_host"));
  }

  {
    // this query should have failed
    EXPECT_EQ(1, tree.get<int>("results.bad.status"));
    const pt::ptree& tree_rows = tree.get_child("results.bad.rows");
    EXPECT_EQ(0, tree_rows.size());
  }

  {
    EXPECT_EQ(0, tree.get<int>("results.minutes.status"));
    const pt::ptree& tree_rows = tree.get_child("results.minutes.rows");
    EXPECT_EQ(1, tree_rows.size());
    auto row = tree_rows.begin();
    EXPECT_GE(row->second.get<int>("minutes"), 0);
    EXPECT_LE(row->second.get<int>("minutes"), 60);
    EXPECT_EQ(getHostname(), row->second.get<std::string>("_source_host"));
  }
}

TEST_F(DistributedTests, test_duplicate_request) {
  // Access to the internal SQL implementation is only available in core.
  auto provider_raw = new MockDistributedProvider();
  provider_raw->queriesJSON_ =
    R"([
      {"query": "SELECT hour FROM time", "id": "hour"}
    ])";
  std::unique_ptr<MockDistributedProvider>
    provider(provider_raw);
  DistributedQueryHandler handler(std::move(provider));

  Status s = handler.doQueries();
  ASSERT_EQ(Status(), s);

  pt::ptree tree;
  std::istringstream json_stream(provider_raw->resultsJSON_);
  ASSERT_NO_THROW(pt::read_json(json_stream, tree));

  EXPECT_EQ(0, tree.get<int>("results.hour.status"));
  const pt::ptree& tree_rows = tree.get_child("results.hour.rows");
  EXPECT_EQ(1, tree_rows.size());
  auto row = tree_rows.begin();
  EXPECT_GE(row->second.get<int>("hour"), 0);
  EXPECT_LE(row->second.get<int>("hour"), 24);
  EXPECT_EQ(getHostname(), row->second.get<std::string>("_source_host"));

  // The second time, 'hour' should not be executed again
  s = handler.doQueries();
  ASSERT_EQ(Status(), s);
  json_stream.str(provider_raw->resultsJSON_);
  ASSERT_NO_THROW(pt::read_json(json_stream, tree));
  EXPECT_EQ(0, tree.get_child("results").size());
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
