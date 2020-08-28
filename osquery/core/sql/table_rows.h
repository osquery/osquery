/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/json/json.h>

#include "query_data.h"
#include "table_row.h"

namespace osquery {

using TableRows = std::vector<TableRowHolder>;

/**
 * @brief Serialize a TableRows object into a JSON array.
 *
 * @param rows the TableRows to serialize.
 * @param doc the managed JSON document.
 * @param arr [output] the output JSON array.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeTableRows(const TableRows& rows,
                          JSON& doc,
                          rapidjson::Document& arr);

/**
 * @brief Serialize a TableRows object into a JSON string.
 *
 * @param rows the TableRows to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeTableRowsJSON(const TableRows& rows, std::string& json);

/// Inverse of serializeTableRows, convert JSON to TableRows.
Status deserializeTableRows(const rapidjson::Value& arr, TableRows& rows);

/// Inverse of serializeTableRowsJSON, convert a JSON string to TableRows.
Status deserializeTableRowsJSON(const std::string& json, TableRows& rows);

} // namespace osquery
