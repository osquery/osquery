/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
  QueryDataTyped added;

  /// vector of removed rows
  QueryDataTyped removed;

  DiffResults() {}
  DiffResults(DiffResults&&) = default;
  DiffResults& operator=(DiffResults&&) = default;

  /**
   * @brief Returns true if there are no results in this diff, otherwise false.
   *
   * @return A bool indicating if this diff has no results.
   */
  inline bool hasNoResults() const {
    return added.empty() && removed.empty();
  }

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
 * @param doc the managed JSON document.
 * @param obj [output] the output JSON object.
 * @param asNumeric true iff numeric values are serialized as such
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeDiffResults(const DiffResults& d,
                            JSON& doc,
                            rapidjson::Document& obj,
                            bool asNumeric);

/**
 * @brief Serialize a DiffResults object into a JSON string.
 *
 * @param d the DiffResults to serialize.
 * @param json [output] the output JSON string.
 * @param asNumeric true iff numeric values are serialized as such
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeDiffResultsJSON(const DiffResults& d,
                                std::string& json,
                                bool asNumeric);

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
DiffResults diff(QueryDataSet& old_, QueryDataTyped& new_);

} // namespace osquery
