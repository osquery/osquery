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

#include <osquery/utils/json.h>

#include "table_row.h"

namespace osquery {

// Right now this is an alias for Row; it will become an implementation of the
// TableRow interface backed by a Row object.
using DynamicTableRow = Row;
/// Syntactic sugar making DynamicRows inside of TableRowHolders easier to work
/// with. This should go away once strongly typed rows are used everywhere.
class DynamicTableRowHolder {
 public:
  DynamicTableRowHolder() : row(new DynamicTableRow()), ptr(row) {}
  DynamicTableRowHolder(
      std::initializer_list<std::pair<const std::string, std::string>> init)
      : row(new DynamicTableRow(init)), ptr(row) {}
  inline operator TableRowHolder &&() {
    return std::move(ptr);
  }
  inline std::string& operator[](const std::string& key) {
    return (*row)[key];
  }
  inline std::string& operator[](std::string&& key) {
    return (*row)[key];
  }
  inline size_t count(const std::string& key) {
    return (*row).count(key);
  }

 private:
  DynamicTableRow* row;
  TableRowHolder ptr;
};
inline DynamicTableRowHolder make_table_row() {
  return DynamicTableRowHolder();
}
inline DynamicTableRowHolder make_table_row(
    std::initializer_list<std::pair<const std::string, std::string>> init) {
  return DynamicTableRowHolder(init);
}

/**
 * @brief Deserialize a DynamicTableRow object from JSON object.
 *
 * @param obj the input JSON value (should be an object).
 * @param r [output] the output DynamicTableRowHolder structure.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status deserializeRow(const rapidjson::Value& doc, DynamicTableRowHolder& r);

} // namespace osquery
