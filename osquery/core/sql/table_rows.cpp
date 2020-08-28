/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "table_rows.h"

namespace rj = rapidjson;

namespace osquery {

Status serializeTableRows(const TableRows& rows, JSON& doc, rj::Document& arr) {
  for (const auto& r : rows) {
    auto row_obj = doc.getObject();
    auto status = r->serialize(doc, row_obj);
    if (!status.ok()) {
      return status;
    }
    doc.push(row_obj, arr);
  }
  return Status::success();
}

Status serializeTableRowsJSON(const TableRows& rows, std::string& json) {
  auto doc = JSON::newArray();

  auto status = serializeTableRows(rows, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

} // namespace osquery
