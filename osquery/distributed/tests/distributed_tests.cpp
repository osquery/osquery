/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>

#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/database/database.h>
#include <osquery/distributed/distributed.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/remote/enroll/enroll.h>
#include <osquery/sql/sql.h>

#include "osquery/remote/tests/test_utils.h"
#include "osquery/sql/sqlite_util.h"
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/json/json.h>

namespace osquery {

DECLARE_string(distributed_tls_read_endpoint);
DECLARE_string(distributed_tls_write_endpoint);

class DistributedTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }

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

  bool startServer() {
    if (!TLSServerRunner::start()) {
      return false;
    }

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
    return true;
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
  std::string json = "{\"query\": \"foo\", \"id\": \"bar\"}";

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
  ASSERT_TRUE(startServer());

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  ASSERT_TRUE(s.ok()) << s.getMessage();
  EXPECT_EQ(s.toString(), "OK");

  auto queries = dist.getPendingQueries();

  EXPECT_EQ(queries.size(), 2U);
  EXPECT_EQ(dist.results_.size(), 0U);
  s = dist.runQueries();
  ASSERT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  queries = dist.getPendingQueries();
  EXPECT_EQ(queries.size(), 0U);
  EXPECT_EQ(dist.results_.size(), 0U);
}
} // namespace osquery
