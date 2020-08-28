/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "table_ipc_json_converter.h"

#include <osquery/core/sql/query_data.h>
#include <osquery/utils/status/status.h>

namespace osquery {
Status TableIPCJSONConverter::JSONToQueryData(const JSON& json_helper,
                                              QueryData& query_data) {
  const auto& rapidjson_doc = json_helper.doc();

  if (!rapidjson_doc.IsObject()) {
    return Status::failure("Expected an object as the root JSON element");
  }

  if (!rapidjson_doc.HasMember("QueryData")) {
    return Status::failure("Missing QueryData member");
  }

  if (!rapidjson_doc["QueryData"].IsArray()) {
    return Status::failure("QueryData member is not an array");
  }

  JSON query_data_array = json_helper.newFromValue(rapidjson_doc["QueryData"]);

  return deserializeQueryDataJSON(query_data_array, query_data);
}

Status TableIPCJSONConverter::queryDataToJSON(const QueryData& query_data,
                                              JSON& json_helper) {
  JSON query_data_doc;
  auto status = serializeQueryDataJSON(query_data, query_data_doc);

  if (!status.ok()) {
    return status;
  }

  json_helper.add("QueryData", query_data_doc.doc());

  return Status::success();
}

Status TableIPCJSONConverter::JSONToLogMessage(const JSON& json_helper,
                                               int& priority,
                                               int& log_type,
                                               std::string& message) {
  const auto& rapidjson_doc = json_helper.doc();

  if (!rapidjson_doc.IsObject()) {
    return Status::failure("Expected an object as the root JSON element");
  }

  if (!rapidjson_doc.HasMember("Priority")) {
    return Status::failure("Missing Priority member");
  }

  if (!rapidjson_doc.HasMember("Message")) {
    return Status::failure("Missing Message member");
  }

  if (!rapidjson_doc.HasMember("LogType")) {
    return Status::failure("Missing LogType member");
  }

  if (!rapidjson_doc["Priority"].IsNumber()) {
    return Status::failure("Security member is not a number");
  }

  if (!rapidjson_doc["Message"].IsString()) {
    return Status::failure("Message member is not a string");
  }

  if (!rapidjson_doc["LogType"].IsNumber()) {
    return Status::failure("LogType member is not a number");
  }

  log_type = rapidjson_doc["LogType"].GetInt();
  message = rapidjson_doc["Message"].GetString();
  priority = rapidjson_doc["Priority"].GetInt();

  return Status::success();
}

Status TableIPCJSONConverter::logMessageToJSON(int priority,
                                               int log_type,
                                               const std::string& message,
                                               JSON& json_helper) {
  json_helper = JSON::newObject();
  json_helper.add("Priority", priority);
  json_helper.add("LogType", log_type);
  json_helper.add("Message", message);

  return Status::success();
}

Status TableIPCJSONConverter::JSONTypeToMessageType(
    const JSON& json_helper, JSONMessageType& message_type) {
  std::string type = json_helper.doc()["Type"].GetString();

  if (type == "Log") {
    message_type = JSONMessageType::Log;
  } else if (type == "QueryData") {
    message_type = JSONMessageType::QueryData;
  } else if (type == "Job") {
    message_type = JSONMessageType::Job;
  } else {
    message_type = JSONMessageType::None;
    return Status::failure("Unsupported JSON message type: " + type);
  }

  return Status::success();
}

} // namespace osquery
