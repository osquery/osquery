/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>
#include <boost/variant.hpp>

#include <osquery/utils/json/json.h>
#include <osquery/utils/status/status.h>

namespace osquery {

/**
 * @brief Alias for string.
 */
using RowData = std::string;

/**
 * @brief A variant type for the SQLite type affinities.
 */
using RowDataTyped = boost::variant<long long, double, std::string>;

/**
 * @brief A single row from a database query
 *
 * Row is a simple map where individual column names are keys, which map to
 * the Row's respective value
 */
using Row = std::map<std::string, RowData>;

/**
 * @brief A single typed row from a database query
 *
 * RowTyped is a simple map where individual column names are keys, which map to
 * the Row's respective type-variant value
 */
using RowTyped = std::map<std::string, RowDataTyped>;

/**
 * @brief A vector of column names associated with a query
 *
 * ColumnNames is a vector of the column names, in order, returned by a query.
 */
using ColumnNames = std::vector<std::string>;

/**
 * @brief Serialize a Row into a JSON document.
 *
 * @param r the Row to serialize.
 * @param cols the TableColumn vector indicating column order
 * @param doc the managed JSON document.
 * @param obj [output] the JSON object to assign values.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeRow(const Row& r,
                    const ColumnNames& cols,
                    JSON& doc,
                    rapidjson::Value& obj);

/**
 * @brief Serialize a RowTyped into a JSON document.
 *
 * @param r the RowTyped to serialize.
 * @param doc the managed JSON document.
 * @param obj [output] the JSON object to assign values.
 * @param asNumeric true iff numeric values are serialized as such
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeRow(const RowTyped& r,
                    JSON& doc,
                    rapidjson::Value& obj,
                    bool asNumeric);

/**
 * @brief Serialize a Row object into a JSON string.
 *
 * @param r the Row to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeRowJSON(const Row& r, std::string& json);

/**
 * @brief Serialize a RowTyped object into a JSON string.
 *
 * @param r the Row to serialize.
 * @param json [output] the output JSON string.
 * @param asNumeric true iff numeric values are serialized as such
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeRowJSON(const RowTyped& r, std::string& json, bool asNumeric);

/**
 * @brief Deserialize a Row object from JSON object.
 *
 * @param obj the input JSON value (should be an object).
 * @param r [output] the output Row structure.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status deserializeRow(const rapidjson::Value& obj, Row& r);

/**
 * @brief Deserialize a RowTyped object from JSON object.
 *
 * @param obj the input JSON value (should be an object).
 * @param r [output] the output Row structure.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status deserializeRow(const rapidjson::Value& obj, RowTyped& r);

/**
 * @brief Deserialize a Row object from a JSON string.
 *
 * @param json the input JSON string.
 * @param r [output] the output Row structure.
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRowJSON(const std::string& json, Row& r);

/**
 * @brief Deserialize a RowTyped object from a JSON string.
 *
 * @param json the input JSON string.
 * @param r [output] the output Row structure.
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRowJSON(const std::string& json, RowTyped& r);

} // namespace osquery
