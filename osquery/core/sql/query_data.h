/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <set>
#include <vector>

#include <osquery/core/sql/row.h>

namespace osquery {

/**
 * @brief The result set returned from a osquery SQL query
 *
 * QueryData is the canonical way to represent the results of SQL queries in
 * osquery. It's just a vector of Rows.
 */
using QueryData = std::vector<Row>;

/**
 * @brief The typed result set returned from a osquery SQL query
 *
 * QueryDataTyped is the canonical way to represent the typed results of SQL
 * queries in osquery. It's just a vector of RowTypeds.
 */
using QueryDataTyped = std::vector<RowTyped>;

/**
 * @brief Set representation result returned from a osquery SQL query
 *
 * QueryDataSet -  It's set of Rows for fast search of a specific row.
 */
using QueryDataSet = std::multiset<RowTyped>;

/**
 * @brief Serialize a QueryData object into a JSON array.
 *
 * @param q the QueryData to serialize.
 * @param cols the TableColumn vector indicating column order.
 * @param doc the managed JSON document.
 * @param arr [output] the output JSON array.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryData(const QueryData& q,
                          const ColumnNames& cols,
                          JSON& doc,
                          rapidjson::Document& arr);

/**
 * @brief Serialize a QueryDataTyped object into a JSON array.
 *
 * @param q the QueryDataTyped to serialize.
 * @param cols the TableColumn vector indicating column order.
 * @param doc the managed JSON document.
 * @param arr [output] the output JSON array.
 * @param asNumeric true iff numeric values are serialized as such
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryData(const QueryDataTyped& q,
                          JSON& doc,
                          rapidjson::Document& arr,
                          bool asNumeric);

/**
 * @brief Serialize a QueryData object into a JSON document.
 *
 * @param q the QueryData to serialize.
 * @param doc [output] the output JSON document.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryDataJSON(const QueryData& q, JSON& doc);

/**
 * @brief Serialize a QueryData object into a JSON string.
 *
 * @param q the QueryData to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryDataJSON(const QueryData& q, std::string& json);

/**
 * @brief Serialize a QueryDataTyped object into a JSON string.
 *
 * @param q the QueryDataTyped to serialize.
 * @param json [output] the output JSON string.
 * @param asNumeric true iff numeric values are serialized as such
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryDataJSON(const QueryDataTyped& q,
                              std::string& json,
                              bool asNumeric);

/// Inverse of serializeQueryData, convert JSON to QueryData.
Status deserializeQueryData(const rapidjson::Value& arr, QueryData& qd);

/// Inverse of serializeQueryData, convert JSON to QueryDataTyped.
Status deserializeQueryData(const rapidjson::Value& arr, QueryDataTyped& qd);

/// Inverse of serializeQueryData, convert JSON to QueryDataSet.
Status deserializeQueryData(const rapidjson::Value& arr, QueryDataSet& qd);

Status deserializeQueryDataJSON(const JSON& doc, QueryData& qd);

/// Inverse of serializeQueryDataJSON, convert a JSON string to QueryData.
Status deserializeQueryDataJSON(const std::string& json, QueryData& qd);

/// Inverse of serializeQueryDataJSON, convert a JSON string to QueryDataSet.
Status deserializeQueryDataJSON(const std::string& json, QueryDataSet& qd);

/**
 * @brief Add a Row to a QueryData if the Row hasn't appeared in the QueryData
 * already
 *
 * Note that this function will iterate through the QueryData list until a
 * given Row is found (or not found). This shouldn't be that significant of an
 * overhead for most use-cases, but it's worth keeping in mind before you use
 * this in it's current state.
 *
 * @param q the QueryDataTyped list to append to
 * @param r the RowTyped to add to q
 *
 * @return true if the Row was added to the QueryData, false if it was not
 */
bool addUniqueRowToQueryData(QueryDataTyped& q, const RowTyped& r);

} // namespace osquery
