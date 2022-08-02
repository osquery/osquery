/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>

#include <gmock/gmock.h>
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
#include <osquery/utils/status/status.h>
#include <osquery/utils/system/time.h>

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

TEST_F(DistributedTests, test_check_and_set_as_running) {
  auto dist = Distributed();

  const auto denylistedQuery = "SELECT * FROM system_info;";
  const auto denylisted = dist.checkAndSetAsRunning(denylistedQuery);
  ASSERT_FALSE(denylisted);

  const auto denylistedQueryKey = hashQuery(denylistedQuery);

  std::string ts1;
  auto status =
      getDatabaseValue(kDistributedRunningQueries, denylistedQueryKey, ts1);
  ASSERT_TRUE(status.ok());
  ASSERT_FALSE(ts1.empty());

  const auto denylisted2 = dist.checkAndSetAsRunning(denylistedQuery);
  ASSERT_TRUE(denylisted2);

  std::string ts2;
  status =
      getDatabaseValue(kDistributedRunningQueries, denylistedQueryKey, ts2);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(ts1, ts2);

  // Change timestamp of the the denylisted query so that it's now expired.
  status =
      setDatabaseValue(kDistributedRunningQueries,
                       denylistedQueryKey,
                       std::to_string(getUnixTime() - denylistDuration() - 60));
  ASSERT_TRUE(status.ok()) << status.getMessage();

  const auto denylisted3 = dist.checkAndSetAsRunning(denylistedQuery);
  ASSERT_FALSE(denylisted3);

  // Cleanup should cleanup the expired query.
  status = dist.cleanupExpiredRunningQueries();
  ASSERT_TRUE(status.ok()) << status.getMessage();

  std::string ts3;
  status =
      getDatabaseValue(kDistributedRunningQueries, denylistedQueryKey, ts3);
  ASSERT_FALSE(status.ok()); // NotFound
  ASSERT_TRUE(ts3.empty());
}

class DistributedMock : public Distributed {
 public:
  DistributedMock() : Distributed() {}
  MOCK_METHOD0(flushCompleted, Status());
};

TEST_F(DistributedTests, test_run_queries_with_denylisted_query) {
  auto dist = DistributedMock();
  // flushCompleted is mocked to avoid sending results in
  // Distributed.runQueries.
  EXPECT_CALL(dist, flushCompleted).Times(2);

  // Simulate a denylisted query by manually marking it as running.
  const auto denylistedQuery = "SELECT * FROM osquery_info;";
  const auto denylisted = dist.checkAndSetAsRunning(denylistedQuery);
  ASSERT_FALSE(denylisted);

  const auto denylistedQueryKey = hashQuery(denylistedQuery);

  const std::string work = R"json(
{
  "queries": {
    "q1": "SELECT * FROM osquery_info;",
    "q2": "SELECT * FROM osquery_info WHERE version > '5.3.0';"
  }
}
)json";
  auto status = dist.acceptWork(work);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  status = dist.runQueries();
  ASSERT_TRUE(status.ok()) << status.getMessage();

  // Query q1 is denylisted, only query q2 ran.
  ASSERT_EQ(dist.results_.size(), 2);
  auto q1Idx = 0, q2Idx = 1;
  if (dist.results_[0].request.id.compare("q2") == 0) {
    q1Idx = 1;
    q2Idx = 0;
  }
  EXPECT_FALSE(dist.results_[q1Idx].status.ok());
  EXPECT_TRUE(dist.results_[q1Idx].results.empty());
  EXPECT_EQ(dist.results_[q1Idx].status.getMessage(), "Denylisted");
  EXPECT_EQ(dist.results_[q1Idx].message, "distributed query is denylisted");
  EXPECT_TRUE(dist.results_[q2Idx].status.ok());
  EXPECT_FALSE(dist.results_[q2Idx].results.empty());

  // Manually clear results.
  dist.results_.clear();

  // Cleanup should not yet cleanup the denylisted query.
  status = dist.cleanupExpiredRunningQueries();
  ASSERT_TRUE(status.ok()) << status.getMessage();
  std::string ts;
  status = getDatabaseValue(kDistributedRunningQueries, denylistedQueryKey, ts);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_FALSE(ts.empty());

  // Change timestamp of the the denylisted query so that it's now expired.
  status =
      setDatabaseValue(kDistributedRunningQueries,
                       denylistedQueryKey,
                       std::to_string(getUnixTime() - denylistDuration() - 60));
  ASSERT_TRUE(status.ok()) << status.getMessage();

  // Query q1 should not by denylisted anymore.
  auto s = dist.acceptWork(work);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  status = dist.runQueries();
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(dist.results_.size(), 2);
  EXPECT_TRUE(dist.results_[0].status.ok());
  EXPECT_TRUE(dist.results_[0].request.id == "q1" ||
              dist.results_[0].request.id == "q2");
  EXPECT_TRUE(dist.results_[1].status.ok());
  EXPECT_TRUE(dist.results_[1].request.id == "q1" ||
              dist.results_[1].request.id == "q2");

  // Query q1 should not be marked as denylisted anymore.
  std::string ts2;
  status =
      getDatabaseValue(kDistributedRunningQueries, denylistedQueryKey, ts2);
  ASSERT_FALSE(status.ok()); // NotFound
  ASSERT_TRUE(ts2.empty());
}
} // namespace osquery
