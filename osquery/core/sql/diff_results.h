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

#include <osquery/core/sql/query_data.h>

namespace osquery {

/**
 * @brief Data structure representing the difference between the results of
 * two queries
 *
 * The representation of two diffed QueryData result sets. Given and old and
 * new QueryData, DiffResults indicates the "added" subset of rows and the
 * "removed" subset of rows.
 */
struct DiffResults : private only_movable {
 public:
  /// vector of added rows
  QueryData added;

  /// vector of removed rows
  QueryData removed;

  DiffResults() {}
  DiffResults(DiffResults&&) = default;
  DiffResults& operator=(DiffResults&&) = default;

  /// equals operator
  bool operator==(const DiffResults& comp) const {
    return (comp.added == added) && (comp.removed == removed);
  }

  /// not equals operator
  bool operator!=(const DiffResults& comp) const {
    return !(*this == comp);
  }
};


/**
 * @brief Serialize a DiffResults object into a JSON object.
 *
 * The object JSON will contain two new keys: added and removed.
 *
 * @param d the DiffResults to serialize.
 * @param cols the TableColumn vector indicating column order.
 * @param doc the managed JSON document.
 * @param obj [output] the output JSON object.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeDiffResults(const DiffResults& d,
                            const ColumnNames& cols,
                            JSON& doc,
                            rapidjson::Document& obj);

/**
 * @brief Serialize a DiffResults object into a JSON string.
 *
 * @param d the DiffResults to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeDiffResultsJSON(const DiffResults& d, std::string& json);

/**
 * @brief Diff QueryDataSet object and QueryData object
 *        and create a DiffResults object
 *
 * @param old_ the "old" set of results.
 * @param new_ the "new" set of results.
 *
 * @return a DiffResults object which indicates the change from old_ to new_
 *
 * @see DiffResults
 */
DiffResults diff(QueryDataSet& old_, QueryData& new_);

} // namespace osquery
