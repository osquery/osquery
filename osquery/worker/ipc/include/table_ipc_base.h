/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include <osquery/core/sql/query_data.h>
#include <osquery/worker/ipc/table_ipc_json_converter.h>

#include <osquery/worker/logging/glog_logger_types.h>

namespace osquery {
template <typename Derived>
class TableIPCBase {
 public:
  Status sendQueryData(const QueryData& query_data) {
    JSON json_helper;
    auto status =
        TableIPCJSONConverter::queryDataToJSON(query_data, json_helper);

    if (!status.ok()) {
      return status;
    }

    json_helper.add("Type", "QueryData");

    std::string json_string;
    status = json_helper.toString(json_string);

    if (!status.ok())
      return status;

    return static_cast<Derived&>(*this).sendJSONString(json_string);
  }

  Status sendLogMessage(int severity,
                        GLOGLogType log_type,
                        const std::string& message) {
    JSON json_helper;
    auto status = TableIPCJSONConverter::logMessageToJSON(
        severity, static_cast<int>(log_type), message, json_helper);

    if (!status.ok()) {
      return status;
    }

    json_helper.add("Type", "Log");

    std::string json_string;
    status = json_helper.toString(json_string);

    if (!status.ok()) {
      return status;
    }

    return static_cast<Derived&>(*this).sendJSONString(json_string);
  }

  Status sendJob(const QueryContext& context) {
    JSON json_helper;
    serializeQueryContextJSON(context, json_helper);
    json_helper.add("Type", "Job");

    std::string json_string;
    auto status = json_helper.toString(json_string);

    if (!status.ok()) {
      return status;
    }

    return static_cast<Derived&>(*this).sendJSONString(json_string);
  }

  Status recvJSONMessage(JSON& json_message, JSONMessageType& message_type) {
    std::string json_string;
    auto status = static_cast<Derived&>(*this).recvJSONString(json_string);

    if (!status.ok()) {
      return status;
    }

    status = json_message.fromString(json_string);

    if (!status.ok()) {
      return status;
    }

    if (!json_message.doc().HasMember("Type")) {
      return Status::failure("No Type member");
    }

    return TableIPCJSONConverter::JSONTypeToMessageType(json_message,
                                                        message_type);
  }

  Status processOneMessage(QueryData* query_results,
                           JSONMessageType& message_type) {
    JSON json_message;
    Status status = recvJSONMessage(json_message, message_type);

    if (!status.ok()) {
      return status;
    }

    switch (message_type) {
    case JSONMessageType::Log: {
      status = static_cast<Derived&>(*this).processLogMessage(json_message);
      break;
    }
    case JSONMessageType::QueryData: {
      if (!query_results) {
        status = Status::failure(1, "Received unexpected QueryData message");
        break;
      }

      status = static_cast<Derived&>(*this).processQueryDataMessage(
          json_message, *query_results);
      break;
    }
    case JSONMessageType::Job: {
      status = static_cast<Derived&>(*this).processJobMessage(json_message);
      break;
    }
    default: {
      status = Status::failure("Invalid message type received, type " +
                               std::to_string(static_cast<int>(message_type)));
      break;
    }
    }

    return status;
  }
};
} // namespace osquery
