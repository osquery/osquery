/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
 * @brief Set representation result returned from a osquery SQL query
 *
 * QueryDataSet -  It's set of Rows for fast search of a specific row.
 */
using QueryDataSet = std::multiset<Row>;

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
 * @brief Serialize a QueryData object into a JSON string.
 *
 * @param q the QueryData to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryDataJSON(const QueryData& q, std::string& json);

/// Inverse of serializeQueryData, convert JSON to QueryData.
Status deserializeQueryData(const rapidjson::Value& arr, QueryData& qd);

/// Inverse of serializeQueryData, convert JSON to QueryDataSet.
Status deserializeQueryData(const rapidjson::Value& arr, QueryDataSet& qd);

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
 * @param q the QueryData list to append to
 * @param r the Row to add to q
 *
 * @return true if the Row was added to the QueryData, false if it was not
 */
bool addUniqueRowToQueryData(QueryData& q, const Row& r);

} // namespace osquery
