/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

#include <osquery/core/sql/query_data.h>
#include <osquery/tables.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/status/status.h>

namespace osquery {
enum class JSONMessageType { None, QueryData, Log, Job };

class TableIPCJSONConverter {
 public:
  static Status JSONToQueryData(const JSON& json_helper, QueryData& query_data);
  static Status queryDataToJSON(const QueryData& query_data, JSON& json_helper);
  static Status JSONToLogMessage(const JSON& json_helper,
                                 int& priority,
                                 int& log_type,
                                 std::string& message);
  static Status logMessageToJSON(int priority,
                                 int log_type,
                                 const std::string& message,
                                 JSON& json_helper);
  static Status JSONTypeToMessageType(const JSON& json_helper,
                                      JSONMessageType& message_type);
};
} // namespace osquery
