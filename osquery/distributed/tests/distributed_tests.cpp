/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <boost/property_tree/ptree.hpp>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/sql/sqlite_util.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace pt = boost::property_tree;

DECLARE_string(distributed_tls_read_endpoint);
DECLARE_string(distributed_tls_write_endpoint);

namespace osquery {

class DistributedTests : public testing::Test {
 protected:
  void SetUp() {
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();
    clearNodeKey();

    distributed_tls_read_endpoint_ =
        Flag::getValue("distributed_tls_read_endpoint");
    Flag::updateValue("distributed_tls_read_endpoint", "/distributed_read");

    distributed_tls_write_endpoint_ =
        Flag::getValue("distributed_tls_write_endpoint");
    Flag::updateValue("distributed_tls_write_endpoint", "/distributed_write");

    Registry::get().setActive("distributed", "tls");
  }

  void TearDown() {
    TLSServerRunner::stop();
    TLSServerRunner::unsetClientConfig();
    clearNodeKey();

    Flag::updateValue("distributed_tls_read_endpoint",
                      distributed_tls_read_endpoint_);
    Flag::updateValue("distributed_tls_write_endpoint",
                      distributed_tls_write_endpoint_);
  }

 protected:
  std::string distributed_tls_read_endpoint_;
  std::string distributed_tls_write_endpoint_;
};

TEST_F(DistributedTests, test_serialize_distributed_query_request) {
  DistributedQueryRequest r;
  r.query = "foo";
  r.id = "bar";

  pt::ptree tree;
  auto s = serializeDistributedQueryRequest(r, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(tree.get<std::string>("query"), "foo");
  EXPECT_EQ(tree.get<std::string>("id"), "bar");
}

TEST_F(DistributedTests, test_deserialize_distributed_query_request) {
  pt::ptree tree;
  tree.put<std::string>("query", "foo");
  tree.put<std::string>("id", "bar");

  DistributedQueryRequest r;
  auto s = deserializeDistributedQueryRequest(tree, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(r.query, "foo");
  EXPECT_EQ(r.id, "bar");
}

TEST_F(DistributedTests, test_deserialize_distributed_query_request_json) {
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

TEST_F(DistributedTests, test_serialize_distributed_query_result) {
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

TEST_F(DistributedTests, test_deserialize_distributed_query_result) {
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

TEST_F(DistributedTests, test_deserialize_distributed_query_result_json) {
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

TEST_F(DistributedTests, test_workflow) {
  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 2U);
  EXPECT_EQ(dist.results_.size(), 0U);
  s = dist.runQueries();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 0U);
  EXPECT_EQ(dist.results_.size(), 0U);
}
}
