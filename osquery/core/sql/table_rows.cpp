/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "table_rows.h"
#include "dynamic_table_row.h"

namespace rj = rapidjson;

namespace osquery {

TableRows tableRowsFromQueryData(QueryData&& rows) {
  TableRows result;

  for (auto&& row : rows) {
    result.push_back(TableRowHolder(new DynamicTableRow(std::move(row))));
  }

  return result;
}

Status serializeTableRows(const TableRows& rows, JSON& doc, rj::Document& arr) {
  for (const auto& r : rows) {
    auto row_obj = doc.getObject();
    for (const auto& i : *r) {
      doc.addRef(i.first, i.second, row_obj);
    }
    doc.push(row_obj, arr);
  }
  return Status();
}

Status serializeTableRowsJSON(const TableRows& rows, std::string& json) {
  auto doc = JSON::newArray();

  auto status = serializeTableRows(rows, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

Status deserializeTableRows(const rj::Value& arr, TableRows& rows) {
  if (!arr.IsArray()) {
    return Status(1);
  }

  for (const auto& i : arr.GetArray()) {
    auto r = make_table_row();
    auto status = deserializeRow(i, r);
    if (!status.ok()) {
      return status;
    }
    rows.push_back(std::move(r));
  }
  return Status();
}

Status deserializeTableRowsJSON(const std::string& json, TableRows& rows) {
  auto doc = JSON::newArray();
  if (!doc.fromString(json) || !doc.doc().IsArray()) {
    return Status(1, "Cannot deserializing JSON");
  }

  return deserializeTableRows(doc.doc(), rows);
}

} // namespace osquery
