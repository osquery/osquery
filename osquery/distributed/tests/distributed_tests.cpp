/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
  void TearDown() override {
    if (server_started_) {
      TLSServerRunner::stop();
      TLSServerRunner::unsetClientConfig();
      clearNodeKey();

      Flag::updateValue("distributed_tls_read_endpoint",
                        distributed_tls_read_endpoint_);
      Flag::updateValue("distributed_tls_write_endpoint",
                        distributed_tls_write_endpoint_);
    }
  }

  void startServer() {
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
    server_started_ = true;
  }

 protected:
  std::string distributed_tls_read_endpoint_;
  std::string distributed_tls_write_endpoint_;

 private:
  bool server_started_{false};
};

TEST_F(DistributedTests, test_serialize_distributed_query_request) {
  DistributedQueryRequest r;
  r.query = "foo";
  r.id = "bar";

  auto doc = JSON::newObject();
  auto s = serializeDistributedQueryRequest(r, doc, doc.doc());
  EXPECT_TRUE(s.ok());
  EXPECT_TRUE(doc.doc().HasMember("query") && doc.doc()["query"].IsString());
  EXPECT_TRUE(doc.doc().HasMember("id") && doc.doc()["id"].IsString());
  if (doc.doc().HasMember("query")) {
    EXPECT_EQ(std::string(doc.doc()["query"].GetString()), "foo");
  }
  if (doc.doc().HasMember("id")) {
    EXPECT_EQ(std::string(doc.doc()["id"].GetString()), "bar");
  }
}

TEST_F(DistributedTests, test_deserialize_distributed_query_request) {
  auto doc = JSON::newObject();
  doc.addRef("query", "foo");
  doc.addRef("id", "bar");

  DistributedQueryRequest r;
  auto s = deserializeDistributedQueryRequest(doc.doc(), r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(r.query, "foo");
  EXPECT_EQ(r.id, "bar");
}

TEST_F(DistributedTests, test_deserialize_distributed_query_request_json) {
  std::string json{"{\"query\": \"foo\", \"id\": \"bar\"}"};

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

  //  rapidjson::Document d(rapidjson::kObjectType);
  auto doc = JSON::newObject();
  auto s = serializeDistributedQueryResult(r, doc, doc.doc());
  EXPECT_TRUE(s.ok());
  //  EXPECT_TRUE(doc.doc().IsObject());
  EXPECT_EQ(doc.doc()["request"]["query"], "foo");
  EXPECT_EQ(doc.doc()["request"]["id"], "bar");
  EXPECT_TRUE(doc.doc()["results"].IsArray());
  for (const auto& q : doc.doc()["results"].GetArray()) {
    for (const auto& row : q.GetObject()) {
      EXPECT_EQ(row.name, "foo");
      EXPECT_EQ(q[row.name], "bar");
    }
  }
}

TEST_F(DistributedTests, test_deserialize_distributed_query_result) {
  auto doc = JSON::newObject();
  auto request_obj = doc.getObject();
  doc.addRef("query", "bar", request_obj);
  doc.addRef("id", "foo", request_obj);

  auto row_obj = doc.getObject();
  doc.addRef("foo", "bar", row_obj);

  auto results_arr = doc.getArray();
  doc.push(row_obj, results_arr);
  doc.add("request", request_obj);
  doc.add("results", results_arr);

  DistributedQueryResult r;
  auto s = deserializeDistributedQueryResult(doc.doc(), r);
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
  ASSERT_TRUE(s.ok());
  EXPECT_EQ(r.request.id, "foo");
  EXPECT_EQ(r.request.query, "bar");
  ASSERT_EQ(r.results.size(), 1_sz);
  EXPECT_EQ(r.results[0]["foo"], "bar");
}

TEST_F(DistributedTests, test_workflow) {
  startServer();

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
