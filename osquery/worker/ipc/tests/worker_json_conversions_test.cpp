/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <string>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>
#include <osquery/utils/status/status.h>
#include <osquery/worker/ipc/table_ipc_base.h>

namespace osquery {

class TestTableIPC : public TableIPCBase<TestTableIPC> {
 public:
  Status sendJSONString(const std::string json_string) {
    auto status = json_helper.fromString(json_string);

    if (!status.ok()) {
      return Status::failure(1, "Failed to parse json_string:\n" + json_string);
    }

    return Status::success();
  }

  Status recvJSONString(std::string& json_string) {
    return json_helper.toString(json_string);
  }

  JSON json_helper;
};

class WorkerJSONConversionsTests : public testing::Test {
 public:
  void verifyMessageType(const rapidjson::Document& rapidjson_doc,
                         const std::string& type) {
    ASSERT_TRUE(rapidjson_doc.HasMember("Type"));
    ASSERT_TRUE(rapidjson_doc["Type"].IsString());

    EXPECT_EQ(std::string(rapidjson_doc["Type"].GetString()), type);
  }
};

TEST_F(WorkerJSONConversionsTests, test_querydata_and_json_conversions) {
  QueryData data;
  Row r1;
  r1["column1"] = "test";
  r1["column2"] = "1";
  data.push_back(r1);

  Row r2;
  r2["column1"] = "test2";
  r2["column2"] = "2";
  data.push_back(r2);

  TestTableIPC ipc;
  auto status = ipc.sendQueryData(data);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  auto& rapidjson_doc = ipc.json_helper.doc();

  ASSERT_TRUE(rapidjson_doc.IsObject());

  verifyMessageType(rapidjson_doc, "QueryData");

  ASSERT_TRUE(rapidjson_doc.HasMember("QueryData"));
  EXPECT_TRUE(rapidjson_doc["QueryData"].IsArray());

  const auto& query_data_array = rapidjson_doc["QueryData"].GetArray();
  ASSERT_EQ(query_data_array.Size(), 2);
  ASSERT_TRUE(query_data_array[0].IsObject());
  ASSERT_TRUE(query_data_array[0].HasMember("column1"));
  EXPECT_TRUE(query_data_array[0]["column1"].IsString());
  EXPECT_EQ(std::string(query_data_array[0]["column1"].GetString()), "test");

  ASSERT_TRUE(query_data_array[0].HasMember("column2"));
  EXPECT_TRUE(query_data_array[0]["column2"].IsString());
  EXPECT_EQ(std::string(query_data_array[0]["column2"].GetString()), "1");

  ASSERT_TRUE(query_data_array[1].IsObject());
  ASSERT_TRUE(query_data_array[1].HasMember("column1"));
  EXPECT_TRUE(query_data_array[1]["column1"].IsString());
  EXPECT_EQ(std::string(query_data_array[1]["column1"].GetString()), "test2");

  ASSERT_TRUE(query_data_array[1].HasMember("column2"));
  EXPECT_TRUE(query_data_array[1]["column2"].IsString());
  EXPECT_EQ(std::string(query_data_array[1]["column2"].GetString()), "2");

  JSONMessageType message_type;
  JSON json_helper;
  status = ipc.recvJSONMessage(json_helper, message_type);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_TRUE(message_type == JSONMessageType::QueryData);

  QueryData read_query_data;
  status = TableIPCJSONConverter::JSONToQueryData(json_helper, read_query_data);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  ASSERT_EQ(read_query_data.size(), 2);
  EXPECT_EQ(read_query_data[0]["column1"], "test");
  EXPECT_EQ(read_query_data[0]["column2"], "1");
  EXPECT_EQ(read_query_data[1]["column1"], "test2");
  EXPECT_EQ(read_query_data[1]["column2"], "2");

  // Try to read the JSON message erroneously as a Log message
  std::string message;
  int priority;
  int log_type_int;
  status = TableIPCJSONConverter::JSONToLogMessage(
      json_helper, priority, log_type_int, message);

  EXPECT_FALSE(status.ok()) << status.getMessage();
}

TEST_F(WorkerJSONConversionsTests, test_log_message_and_json_conversions) {
  TestTableIPC ipc;
  auto status =
      ipc.sendLogMessage(1, GLOGLogType::LOG, "This is a test message");

  ASSERT_TRUE(status.ok()) << status.getMessage();

  auto& rapidjson_doc = ipc.json_helper.doc();

  ASSERT_TRUE(rapidjson_doc.IsObject());

  verifyMessageType(rapidjson_doc, "Log");

  ASSERT_TRUE(rapidjson_doc.HasMember("Priority"));
  EXPECT_TRUE(rapidjson_doc["Priority"].IsNumber());
  EXPECT_EQ(rapidjson_doc["Priority"].GetInt(), 1);

  ASSERT_TRUE(rapidjson_doc.HasMember("Message"));
  EXPECT_TRUE(rapidjson_doc["Message"].IsString());
  EXPECT_EQ(std::string(rapidjson_doc["Message"].GetString()),
            "This is a test message");

  JSONMessageType message_type;
  JSON json_helper;
  status = ipc.recvJSONMessage(json_helper, message_type);
  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(message_type == JSONMessageType::Log);

  int priority = 0;
  int log_type_int = 0;
  std::string message;
  status = TableIPCJSONConverter::JSONToLogMessage(
      json_helper, priority, log_type_int, message);

  ASSERT_TRUE(status.ok()) << status.getMessage();

  EXPECT_EQ(priority, 1);
  EXPECT_EQ(message, "This is a test message");

  QueryData query_data;
  status = TableIPCJSONConverter::JSONToQueryData(json_helper, query_data);

  EXPECT_FALSE(status.ok()) << status.getMessage();
}

TEST_F(WorkerJSONConversionsTests, test_job_and_json_conversions) {
  TestTableIPC ipc;
  QueryContext context;

  context.constraints["job_test_1"].add(Constraint(ConstraintOperator::EQUALS));
  context.constraints["job_test_1"].add(
      Constraint(ConstraintOperator::GREATER_THAN));
  context.constraints["job_test_2"].add(Constraint(ConstraintOperator::LIKE));
  context.constraints["job_test_2"].add(Constraint(ConstraintOperator::MATCH));

  UsedColumns used_columns;
  used_columns.emplace("job_test_1");
  used_columns.emplace("job_test_2");
  used_columns.emplace("job_test_3");
  context.colsUsed = std::move(used_columns);

  auto status = ipc.sendJob(context);

  ASSERT_TRUE(status.ok()) << status.getMessage();

  auto& rapidjson_doc = ipc.json_helper.doc();

  ASSERT_TRUE(rapidjson_doc.IsObject());

  verifyMessageType(rapidjson_doc, "Job");

  ASSERT_TRUE(rapidjson_doc.HasMember("constraints"));
  ASSERT_TRUE(rapidjson_doc["constraints"].IsArray());

  auto constraints = rapidjson_doc["constraints"].GetArray();

  ASSERT_EQ(constraints.Size(), 2);

  for (const auto& constraint : constraints) {
    ASSERT_TRUE(constraint.IsObject());
    ASSERT_TRUE(constraint.HasMember("name"));
    ASSERT_TRUE(constraint["name"].IsString());
    ASSERT_TRUE(constraint.HasMember("list"));
    ASSERT_TRUE(constraint["list"].IsArray());
    auto ops = constraint["list"].GetArray();

    ASSERT_EQ(ops.Size(), 2);

    for (const auto& op : ops) {
      ASSERT_TRUE(op.IsObject());
      ASSERT_TRUE(op.HasMember("op"));
      ASSERT_TRUE(op["op"].IsNumber());
    }
  }

  ASSERT_TRUE(rapidjson_doc.HasMember("colsUsed"));
  ASSERT_TRUE(rapidjson_doc["colsUsed"].IsArray());
  EXPECT_EQ(rapidjson_doc["colsUsed"].Size(), 3);

  QueryContext read_query_context;

  JSONMessageType message_type;
  JSON json_helper;
  status = ipc.recvJSONMessage(json_helper, message_type);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_TRUE(message_type == JSONMessageType::Job);

  status = deserializeQueryContextJSON(json_helper, read_query_context);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  ASSERT_TRUE(read_query_context.colsUsed);

  ASSERT_EQ(read_query_context.colsUsed->size(), 3);

  ASSERT_EQ(read_query_context.colsUsed.get().count("job_test_1"), 1);
  ASSERT_EQ(read_query_context.colsUsed.get().count("job_test_2"), 1);
  ASSERT_EQ(read_query_context.colsUsed.get().count("job_test_3"), 1);

  ASSERT_EQ(read_query_context.constraints.size(), 2);
  ASSERT_EQ(read_query_context.constraints.count("job_test_1"), 1);
  ASSERT_EQ(read_query_context.constraints.count("job_test_2"), 1);

  ASSERT_TRUE(read_query_context.constraints["job_test_1"].exists(
      ConstraintOperator::EQUALS));
  ASSERT_TRUE(read_query_context.constraints["job_test_1"].exists(
      ConstraintOperator::GREATER_THAN));
  ASSERT_TRUE(read_query_context.constraints["job_test_2"].exists(
      ConstraintOperator::LIKE));
  ASSERT_TRUE(read_query_context.constraints["job_test_2"].exists(
      ConstraintOperator::MATCH));
}
} // namespace osquery
