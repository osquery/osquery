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

#include <rapidjson/prettywriter.h>

#undef GetObject

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

  rapidjson::Document d(rapidjson::kObjectType);
  auto s = serializeDistributedQueryRequest(r, d);
  EXPECT_TRUE(s.ok());
  EXPECT_TRUE(d.HasMember("query") && d["query"].IsString());
  EXPECT_TRUE(d.HasMember("id") && d["id"].IsString());
  if (d.HasMember("query")) {
    EXPECT_EQ(std::string(d["query"].GetString()), "foo");
  }
  if (d.HasMember("id")) {
    EXPECT_EQ(std::string(d["id"].GetString()), "bar");
  }
}

TEST_F(DistributedTests, test_deserialize_distributed_query_request) {
  rapidjson::Document d(rapidjson::kObjectType);
  d.AddMember(rapidjson::Value("query", d.GetAllocator()).Move(),
              rapidjson::Value("foo", d.GetAllocator()),
              d.GetAllocator());

  d.AddMember(rapidjson::Value("id", d.GetAllocator()).Move(),
              rapidjson::Value("bar", d.GetAllocator()).Move(),
              d.GetAllocator());

  DistributedQueryRequest r;
  auto s = deserializeDistributedQueryRequest(d, r);
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
  r.columns = {"foo"};
  rapidjson::Document d(rapidjson::kObjectType);
  auto s = serializeDistributedQueryResult(r, d);
  EXPECT_TRUE(s.ok());
  EXPECT_TRUE(d.IsObject());
  EXPECT_EQ(d["request"]["query"], "foo");
  EXPECT_EQ(d["request"]["id"], "bar");
  EXPECT_TRUE(d["results"].IsArray());
  for (const auto& q : d["results"].GetArray()) {
    for (const auto& row : q.GetObject()) {
      EXPECT_EQ(row.name, "foo");
      EXPECT_EQ(q[row.name], "bar");
    }
  }
}

TEST_F(DistributedTests, test_deserialize_distributed_query_result) {
  rapidjson::Document query_result(rapidjson::kObjectType);
  rapidjson::Document request(rapidjson::kObjectType);
  rapidjson::Value row(rapidjson::kObjectType);
  rapidjson::Document results(rapidjson::kArrayType);

  request.AddMember(
      rapidjson::Value("query", query_result.GetAllocator()).Move(),
      rapidjson::Value("bar", query_result.GetAllocator()),
      query_result.GetAllocator());

  request.AddMember(rapidjson::Value("id", query_result.GetAllocator()).Move(),
                    rapidjson::Value("foo", query_result.GetAllocator()).Move(),
                    query_result.GetAllocator());

  row.AddMember(rapidjson::Value("foo", query_result.GetAllocator()).Move(),
                rapidjson::Value("bar", query_result.GetAllocator()).Move(),
                query_result.GetAllocator());

  results.PushBack(rapidjson::Value(row, request.GetAllocator()).Move(),
                   request.GetAllocator());

  query_result.AddMember("request",
                         rapidjson::Value(request, query_result.GetAllocator()),
                         query_result.GetAllocator());
  query_result.AddMember("results",
                         rapidjson::Value(results, query_result.GetAllocator()),
                         query_result.GetAllocator());

  DistributedQueryResult r;
  auto s = deserializeDistributedQueryResult(query_result, r);
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
